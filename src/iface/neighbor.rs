// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use heapless::LinearMap;

use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;
use crate::time::{Duration, Instant};
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::Ipv6Address;
use crate::wire::{HardwareAddress, IpAddress};

#[cfg(feature = "proto-ipv6-rio")]
const MAX_RTR_PROBES: u8 = 3;

#[cfg(feature = "proto-ipv6-rio")]
const RTR_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Resolution state for an IPv6 router.
#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum RouterResolutionState {
    /// No failed resolution attempt is known.
    Unknown,
    /// Resolution attempts are still in progress.
    Pending,
    /// The bounded resolution attempt count was exhausted.
    Unreachable,
}

#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RouterResolution {
    probes_sent: u8,
    last_probe_at: Instant,
    probe_requested: bool,
    recovery_probe_sent: bool,
}

#[cfg(feature = "proto-ipv6-rio")]
impl RouterResolution {
    fn unreachable_at(&self) -> Instant {
        self.last_probe_at + Cache::SILENT_TIME
    }

    fn retry_at(&self) -> Instant {
        if self.recovery_probe_sent {
            // Recovery probes do not re-enter the one-second resolution
            // grace period, so their RFC 4191 throttle starts when sent.
            self.last_probe_at + RTR_PROBE_RETRY_INTERVAL
        } else {
            self.unreachable_at() + RTR_PROBE_RETRY_INTERVAL
        }
    }

    fn state(&self, now: Instant) -> RouterResolutionState {
        if self.recovery_probe_sent {
            // A recovery probe is deliberately separate from address
            // resolution. Keep data on the fallback until an NA proves that
            // the avoided router is reachable again.
            RouterResolutionState::Unreachable
        } else if self.probes_sent < MAX_RTR_PROBES || now < self.unreachable_at() {
            RouterResolutionState::Pending
        } else {
            RouterResolutionState::Unreachable
        }
    }

    fn poll_at(&self, now: Instant) -> Option<Instant> {
        match self.state(now) {
            RouterResolutionState::Unknown => None,
            RouterResolutionState::Pending if self.probes_sent < MAX_RTR_PROBES => {
                let retry_at = self.last_probe_at + Cache::SILENT_TIME;
                (now < retry_at).then_some(retry_at)
            }
            RouterResolutionState::Pending => Some(self.unreachable_at()),
            RouterResolutionState::Unreachable if self.probe_requested => {
                Some(self.retry_at().max(now))
            }
            RouterResolutionState::Unreachable => None,
        }
    }
}

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbor {
    hardware_addr: HardwareAddress,
    expires_at: Instant,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(HardwareAddress),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A neighbor cache backed by a map.
#[derive(Debug)]
pub struct Cache {
    storage: LinearMap<IpAddress, Neighbor, IFACE_NEIGHBOR_CACHE_COUNT>,
    silent_until: Instant,
    #[cfg(feature = "proto-ipv6-rio")]
    router_resolution: LinearMap<Ipv6Address, RouterResolution, IFACE_NEIGHBOR_CACHE_COUNT>,
}

impl Cache {
    /// Minimum delay between discovery requests, in milliseconds.
    pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);

    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub fn new() -> Self {
        Self {
            storage: LinearMap::new(),
            silent_until: Instant::from_millis(0),
            #[cfg(feature = "proto-ipv6-rio")]
            router_resolution: LinearMap::new(),
        }
    }

    pub fn reset_expiry_if_existing(
        &mut self,
        protocol_addr: IpAddress,
        source_hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Some(Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get_mut(&protocol_addr)
            && source_hardware_addr == *hardware_addr
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
            #[cfg(feature = "proto-ipv6-rio")]
            match protocol_addr {
                IpAddress::Ipv6(address) => {
                    self.router_resolution.remove(&address);
                }
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_) => {}
            }
        }
    }

    pub fn fill(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(protocol_addr, hardware_addr, expires_at);
    }

    pub fn fill_with_expiration(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        expires_at: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        #[cfg(feature = "proto-ipv6-rio")]
        match protocol_addr {
            IpAddress::Ipv6(address) => {
                self.router_resolution.remove(&address);
            }
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => {}
        }

        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
        };
        match self.storage.insert(protocol_addr, neighbor) {
            Ok(Some(old_neighbor)) => {
                if old_neighbor.hardware_addr != hardware_addr {
                    net_trace!(
                        "replaced {} => {} (was {})",
                        protocol_addr,
                        hardware_addr,
                        old_neighbor.hardware_addr
                    );
                }
            }
            Ok(None) => {
                net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
            }
            Err((protocol_addr, neighbor)) => {
                // If we're going down this branch, it means the cache is full, and we need to evict an entry.
                let old_protocol_addr = *self
                    .storage
                    .iter()
                    .min_by_key(|(_, neighbor)| neighbor.expires_at)
                    .expect("empty neighbor cache storage")
                    .0;

                let _old_neighbor = self.storage.remove(&old_protocol_addr).unwrap();
                match self.storage.insert(protocol_addr, neighbor) {
                    Ok(None) => {
                        net_trace!(
                            "filled {} => {} (evicted {} => {})",
                            protocol_addr,
                            hardware_addr,
                            old_protocol_addr,
                            _old_neighbor.hardware_addr
                        );
                    }
                    // We've covered everything else above.
                    _ => unreachable!(),
                }
            }
        }
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        assert!(protocol_addr.is_unicast());

        if let Some(&Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get(protocol_addr)
            && timestamp < expires_at
        {
            return Answer::Found(hardware_addr);
        }

        if timestamp < self.silent_until {
            Answer::RateLimited
        } else {
            Answer::NotFound
        }
    }

    pub(crate) fn limit_rate(&mut self, timestamp: Instant) {
        self.silent_until = timestamp + Self::SILENT_TIME;
    }

    /// Record that a Neighbor Solicitation was sent to an IPv6 router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn record_router_probe(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.router_resolution.get_mut(&address) {
            if resolution.probes_sent < MAX_RTR_PROBES {
                resolution.probes_sent += 1;
                resolution.last_probe_at = now;
            }
            return;
        }

        let resolution = RouterResolution {
            probes_sent: 1,
            last_probe_at: now,
            probe_requested: false,
            recovery_probe_sent: false,
        };
        if self.router_resolution.insert(address, resolution).is_err() {
            // Keep tracking bounded and deterministic. The oldest attempt is
            // least useful for current route selection.
            let oldest = *self
                .router_resolution
                .iter()
                .min_by_key(|(_, resolution)| resolution.last_probe_at)
                .expect("empty router resolution storage")
                .0;
            self.router_resolution.remove(&oldest);
            self.router_resolution
                .insert(address, resolution)
                .expect("router resolution storage has room after eviction");
        }
    }

    /// Return the current resolution state for an IPv6 router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_resolution_state(
        &self,
        address: &Ipv6Address,
        now: Instant,
    ) -> RouterResolutionState {
        // Never-seen routers must stay Unknown: RFC 4191 requires hosts to
        // assume reachability when they have no contrary information.
        self.router_resolution
            .get(address)
            .map_or(RouterResolutionState::Unknown, |resolution| {
                resolution.state(now)
            })
    }

    /// Return whether an IPv6 router is known to be unreachable.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn is_router_unreachable(&self, address: &Ipv6Address, now: Instant) -> bool {
        self.router_resolution_state(address, now) == RouterResolutionState::Unreachable
    }

    /// Request a recovery probe because useful traffic selected a fallback.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn request_router_probe(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.router_resolution.get_mut(&address)
            && resolution.state(now) == RouterResolutionState::Unreachable
        {
            // The request is remembered until the per-router one-minute
            // limit permits it; no probe is generated without useful traffic.
            resolution.probe_requested = true;
        }
    }

    /// Return a requested recovery probe that may be sent now.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_probe_required(&self, now: Instant) -> Option<Ipv6Address> {
        self.router_resolution
            .iter()
            .find_map(|(address, resolution)| {
                (resolution.state(now) == RouterResolutionState::Unreachable
                    && resolution.probe_requested
                    && now >= resolution.retry_at())
                .then_some(*address)
            })
    }

    /// Record a separately dispatched RFC 4191 recovery probe.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_recovery_probe_sent(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.router_resolution.get_mut(&address) {
            resolution.probes_sent = MAX_RTR_PROBES;
            resolution.last_probe_at = now;
            resolution.probe_requested = false;
            resolution.recovery_probe_sent = true;
        }
    }

    /// Stop tracking a router that is no longer advertised.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn discard_router_resolution(&mut self, address: &Ipv6Address) {
        self.router_resolution.remove(address);
    }

    /// Return the next router-resolution state transition.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_resolution_poll_at(&self, now: Instant) -> Option<Instant> {
        self.router_resolution
            .values()
            .filter_map(|resolution| resolution.poll_at(now))
            .min()
    }

    pub(crate) fn flush(&mut self) {
        self.storage.clear();
        #[cfg(feature = "proto-ipv6-rio")]
        self.router_resolution.clear();
    }
}

#[cfg(feature = "medium-ethernet")]
#[cfg(test)]
mod test {
    use super::*;
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    use crate::wire::ipv4::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    use crate::wire::EthernetAddress;

    const HADDR_A: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    const HADDR_B: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 2]));
    const HADDR_C: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 3]));
    const HADDR_D: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 4]));

    #[test]
    fn test_fill() {
        let mut cache = Cache::new();

        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(50));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(200));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(300));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_hush() {
        let mut cache = Cache::new();

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(2000)),
            Answer::NotFound
        );
    }

    #[test]
    fn test_flush() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.flush();
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_state() {
        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);

        // A never-seen router has no negative reachability information.
        assert_eq!(
            cache.router_resolution_state(&router, t0),
            RouterResolutionState::Unknown
        );
        assert!(!cache.is_router_unreachable(&router, t0));

        cache.record_router_probe(router, t0);
        assert_eq!(
            cache.router_resolution_state(&router, t0),
            RouterResolutionState::Pending
        );
        assert_eq!(
            cache.router_resolution_poll_at(t0),
            Some(t0 + Cache::SILENT_TIME)
        );

        let t1 = t0 + Cache::SILENT_TIME;
        cache.record_router_probe(router, t1);
        let t2 = t1 + Cache::SILENT_TIME;
        cache.record_router_probe(router, t2);

        let unreachable_at = t2 + Cache::SILENT_TIME;
        assert_eq!(
            cache.router_resolution_state(&router, t2),
            RouterResolutionState::Pending
        );
        assert!(cache.is_router_unreachable(&router, unreachable_at));

        let retry_at = unreachable_at + RTR_PROBE_RETRY_INTERVAL;
        assert_eq!(cache.router_resolution_poll_at(unreachable_at), None);
        cache.request_router_probe(router, unreachable_at);
        assert_eq!(
            cache.router_resolution_poll_at(unreachable_at),
            Some(retry_at)
        );
        assert_eq!(
            cache.router_resolution_state(&router, retry_at),
            RouterResolutionState::Unreachable
        );
        assert_eq!(cache.router_probe_required(retry_at), Some(router));

        cache.router_recovery_probe_sent(router, retry_at);
        assert_eq!(
            cache.router_resolution_state(&router, retry_at),
            RouterResolutionState::Unreachable
        );
        assert_eq!(cache.router_resolution_poll_at(retry_at), None);
        cache.request_router_probe(router, retry_at);
        assert_eq!(
            cache.router_resolution_poll_at(retry_at),
            Some(retry_at + RTR_PROBE_RETRY_INTERVAL)
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_cleared_on_fill() {
        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);

        cache.record_router_probe(router, t0);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME * 2);
        let unreachable_at = t0 + Cache::SILENT_TIME * 3;
        assert!(cache.is_router_unreachable(&router, unreachable_at));

        cache.fill(router.into(), HADDR_A, unreachable_at);
        assert_eq!(
            cache.router_resolution_state(&router, unreachable_at),
            RouterResolutionState::Unknown
        );
        assert!(!cache.is_router_unreachable(&router, unreachable_at));
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_cleared_on_neighbor_refresh() {
        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);

        cache.fill(router.into(), HADDR_A, t0);
        cache.record_router_probe(router, t0);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME * 2);
        let unreachable_at = t0 + Cache::SILENT_TIME * 3;
        assert!(cache.is_router_unreachable(&router, unreachable_at));

        cache.reset_expiry_if_existing(router.into(), HADDR_A, unreachable_at);
        assert_eq!(
            cache.router_resolution_state(&router, unreachable_at),
            RouterResolutionState::Unknown
        );
    }
}
