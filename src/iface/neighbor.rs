// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use heapless::LinearMap;

use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;
use crate::time::{Duration, Instant};
#[cfg(feature = "proto-ipv6")]
use crate::wire::Ipv6Address;
use crate::wire::{HardwareAddress, IpAddress};

/// Number of Neighbor Solicitations sent before address resolution is abandoned.
///
/// See [RFC 4861 § 10] `MAX_MULTICAST_SOLICIT`.
///
/// [RFC 4861 § 10]: https://datatracker.ietf.org/doc/html/rfc4861#section-10
#[cfg(feature = "proto-ipv6")]
const MAX_NEIGHBOR_PROBES: u8 = 3;

/// An in-progress address resolution for an IPv6 neighbor.
///
/// [RFC 4861 § 7.2.5] only permits a Neighbor Advertisement to create state when
/// the host has a Neighbor Cache entry for the target. This tracks the INCOMPLETE
/// entries that ordinary address resolution creates, which have no link-layer
/// address and so cannot be represented in [`Cache::storage`].
///
/// [RFC 4861 § 7.2.5]: https://datatracker.ietf.org/doc/html/rfc4861#section-7.2.5
#[cfg(feature = "proto-ipv6")]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct NeighborResolution {
    probes_sent: u8,
    last_probe_at: Instant,
}

#[cfg(feature = "proto-ipv6")]
impl NeighborResolution {
    fn new(now: Instant) -> Self {
        Self {
            probes_sent: 1,
            last_probe_at: now,
        }
    }

    fn failure_at(&self) -> Instant {
        let remaining_windows = u32::from(MAX_NEIGHBOR_PROBES.saturating_sub(self.probes_sent)) + 1;
        self.last_probe_at + Cache::SILENT_TIME * remaining_windows
    }

    fn is_outstanding(&self, now: Instant) -> bool {
        // The first two timeouts schedule another multicast solicitation, so
        // the INCOMPLETE entry remains valid between retransmissions. A
        // synthetic final deadline also bounds abandoned resolution attempts.
        self.last_probe_at <= now && now < self.failure_at()
    }

    fn record_probe(&mut self, now: Instant) {
        if self.is_outstanding(now) {
            self.probes_sent = self.probes_sent.saturating_add(1).min(MAX_NEIGHBOR_PROBES);
        } else {
            // A later solicitation starts a fresh resolution cycle after the
            // previous cycle reached its bounded failure point.
            self.probes_sent = 1;
        }
        self.last_probe_at = now;
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
    /// RFC 4861 IsRouter state for this live Neighbor Cache entry.
    #[cfg(feature = "proto-ipv6")]
    is_router: bool,
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
    #[cfg(feature = "proto-ipv6")]
    neighbor_resolution: LinearMap<Ipv6Address, NeighborResolution, IFACE_NEIGHBOR_CACHE_COUNT>,
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
            #[cfg(feature = "proto-ipv6")]
            neighbor_resolution: LinearMap::new(),
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
            ..
        }) = self.storage.get_mut(&protocol_addr)
            && source_hardware_addr == *hardware_addr
            && {
                #[cfg(feature = "proto-ipv6")]
                {
                    match protocol_addr {
                        // An expired IPv6 entry is absent as far as RFC 4861
                        // IsRouter state is concerned, so it must not be
                        // resurrected by unrelated inbound traffic. IPv4
                        // retains its original passive refresh behavior.
                        IpAddress::Ipv6(_) => timestamp < *expires_at,
                        #[cfg(feature = "proto-ipv4")]
                        IpAddress::Ipv4(_) => true,
                    }
                }
                #[cfg(not(feature = "proto-ipv6"))]
                {
                    true
                }
            }
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
            // Any inbound packet can refresh this mapping, but RFC 4861
            // reachability requires a solicited NA or a real upper-layer hint,
            // so IsRouter state is deliberately left untouched here.
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
        #[cfg(feature = "proto-ipv6")]
        if matches!(protocol_addr, IpAddress::Ipv6(_))
            && self
                .storage
                .get(&protocol_addr)
                .is_some_and(|neighbor| timestamp >= neighbor.expires_at)
        {
            // RFC 4861 treats an expired Neighbor Cache entry as absent.
            // Removing it before a generic fill prevents stale IsRouter state
            // from being inherited by what is semantically a new IPv6 entry.
            // IPv4 keeps its original replace-in-place behavior.
            self.storage.remove(&protocol_addr);
        }
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

        #[cfg(feature = "proto-ipv6")]
        let is_router = self
            .storage
            .get(&protocol_addr)
            .is_some_and(|neighbor| neighbor.is_router);

        // Fills also come from unsolicited discovery traffic and static cache
        // maintenance, neither of which proves bidirectional reachability.
        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
            // Generic fills preserve explicit live IsRouter state. A newly
            // inserted mapping starts as a host until an RA/NA says otherwise.
            #[cfg(feature = "proto-ipv6")]
            is_router,
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
        #[cfg(feature = "proto-ipv6")]
        match protocol_addr {
            IpAddress::Ipv6(target) => {
                // A learned mapping completes only the matching INCOMPLETE
                // entry; concurrent attempts for other neighbors stay valid.
                self.neighbor_resolution.remove(&target);
            }
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => {}
        }
    }

    /// Apply an ND-sourced link-layer mapping.
    ///
    /// Returns whether the live link-layer mapping was created or changed.
    #[cfg(feature = "proto-ipv6")]
    fn fill_ndisc_mapping(
        &mut self,
        protocol_addr: Ipv6Address,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> bool {
        let protocol_addr = IpAddress::Ipv6(protocol_addr);
        let mapping_created_or_changed = self
            .storage
            .get(&protocol_addr)
            .filter(|neighbor| timestamp < neighbor.expires_at)
            .is_none_or(|neighbor| neighbor.hardware_addr != hardware_addr);
        self.fill(protocol_addr, hardware_addr, timestamp);
        mapping_created_or_changed
    }

    /// Apply a valid Router Advertisement mapping and set IsRouter to TRUE.
    ///
    /// Returns whether the live link-layer mapping was created or changed.
    #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv6-slaac"))]
    pub(crate) fn fill_from_router_advertisement(
        &mut self,
        protocol_addr: Ipv6Address,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> bool {
        let mapping_created_or_changed =
            self.fill_ndisc_mapping(protocol_addr, hardware_addr, timestamp);
        let _marked = self.set_router_if_live(&protocol_addr, true, timestamp);
        debug_assert!(_marked.is_some(), "the RA mapping was just inserted");
        mapping_created_or_changed
    }

    /// Apply a valid Neighbor Solicitation mapping without inventing IsRouter.
    ///
    /// An existing live entry retains its flag; a new or expired entry starts
    /// with IsRouter FALSE. Returns whether the mapping was created or changed.
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn fill_from_neighbor_solicitation(
        &mut self,
        protocol_addr: Ipv6Address,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> bool {
        self.fill_ndisc_mapping(protocol_addr, hardware_addr, timestamp)
    }

    /// Set IsRouter on an existing live IPv6 Neighbor Cache entry.
    ///
    /// An RA without an SLLA uses this to mark an existing entry TRUE. An
    /// accepted NA passes its Router flag and uses the returned prior value for
    /// the [RFC 4861 § 7.2.5] TRUE-to-FALSE transition. Returns `None` when the
    /// entry is absent or expired.
    ///
    /// [RFC 4861 § 7.2.5]: https://datatracker.ietf.org/doc/html/rfc4861#section-7.2.5
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn set_router_if_live(
        &mut self,
        protocol_addr: &Ipv6Address,
        is_router: bool,
        timestamp: Instant,
    ) -> Option<bool> {
        let neighbor = self.storage.get_mut(&IpAddress::Ipv6(*protocol_addr))?;
        if timestamp >= neighbor.expires_at {
            return None;
        }
        let previous = neighbor.is_router;
        neighbor.is_router = is_router;
        Some(previous)
    }

    /// Return the IsRouter value of a live IPv6 Neighbor Cache entry.
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn is_router(&self, protocol_addr: &Ipv6Address, timestamp: Instant) -> bool {
        self.storage
            .get(&IpAddress::Ipv6(*protocol_addr))
            .is_some_and(|neighbor| timestamp < neighbor.expires_at && neighbor.is_router)
    }

    /// Record an actually dispatched IPv6 Neighbor Solicitation.
    ///
    /// This stands in for the INCOMPLETE Neighbor Cache entry that [RFC 4861
    /// § 7.2.2] creates when address resolution starts.
    ///
    /// [RFC 4861 § 7.2.2]: https://datatracker.ietf.org/doc/html/rfc4861#section-7.2.2
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn record_neighbor_probe(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.neighbor_resolution.get_mut(&address) {
            resolution.record_probe(now);
            return;
        }

        let resolution = NeighborResolution::new(now);
        if let Err((address, resolution)) = self.neighbor_resolution.insert(address, resolution) {
            // Ordinary lookups may overlap across sockets even though packet
            // transmission is globally rate-limited. Prefer reclaiming a
            // completed failure; otherwise discard the oldest bounded record.
            let victim = self
                .neighbor_resolution
                .iter()
                .min_by_key(|(_, candidate)| {
                    (candidate.is_outstanding(now), candidate.last_probe_at)
                })
                .map(|(target, _)| *target);
            if let Some(victim) = victim {
                self.neighbor_resolution.remove(&victim);
                let _ = self.neighbor_resolution.insert(address, resolution);
            }
        }
    }

    /// Return whether address resolution for this target is still incomplete.
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn neighbor_probe_outstanding(&self, address: &Ipv6Address, now: Instant) -> bool {
        self.neighbor_resolution
            .get(address)
            .is_some_and(|resolution| resolution.is_outstanding(now))
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        assert!(protocol_addr.is_unicast());

        if let Some(&Neighbor {
            expires_at,
            hardware_addr,
            ..
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

    pub(crate) fn flush(&mut self) {
        self.storage.clear();
        #[cfg(feature = "proto-ipv6")]
        self.neighbor_resolution.clear();
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

    #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv6-slaac"))]
    #[test]
    fn test_ndisc_mapping_reports_changes_and_preserves_is_router() {
        let mut cache = Cache::new();
        let address = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);

        assert!(cache.fill_from_neighbor_solicitation(address, HADDR_A, t0));
        assert!(!cache.is_router(&address, t0));
        assert!(!cache.fill_from_neighbor_solicitation(address, HADDR_A, t0));

        assert_eq!(cache.set_router_if_live(&address, true, t0), Some(false));
        assert!(cache.is_router(&address, t0));

        // NS and generic mapping refreshes must retain explicit IsRouter state.
        assert!(cache.fill_from_neighbor_solicitation(address, HADDR_B, t0));
        assert!(cache.is_router(&address, t0));
        cache.fill(address.into(), HADDR_C, t0);
        assert!(cache.is_router(&address, t0));

        assert!(!cache.fill_from_router_advertisement(address, HADDR_C, t0));
        assert!(cache.fill_from_router_advertisement(address, HADDR_D, t0));
        assert!(cache.is_router(&address, t0));

        // An NA consumer can clear the flag after observing its prior value.
        assert_eq!(cache.set_router_if_live(&address, false, t0), Some(true));
        assert!(!cache.is_router(&address, t0));
    }

    #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv6-slaac"))]
    #[test]
    fn test_expired_neighbor_has_no_is_router_state() {
        let mut cache = Cache::new();
        let address = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);
        let expired_at = t0 + Cache::ENTRY_LIFETIME;

        assert!(cache.fill_from_router_advertisement(address, HADDR_A, t0));
        assert!(cache.is_router(&address, t0));
        assert!(!cache.is_router(&address, expired_at));
        assert_eq!(cache.set_router_if_live(&address, true, expired_at), None);

        // A generic packet refresh cannot resurrect an expired mapping.
        cache.reset_expiry_if_existing(address.into(), HADDR_A, expired_at);
        assert_eq!(cache.lookup(&address.into(), expired_at), Answer::NotFound);

        // A subsequent NS creates a host entry rather than inheriting the
        // expired router flag.
        assert!(cache.fill_from_neighbor_solicitation(address, HADDR_A, expired_at));
        assert!(!cache.is_router(&address, expired_at));
        assert_eq!(
            cache.set_router_if_live(&address, true, expired_at),
            Some(false)
        );
        assert!(cache.is_router(&address, expired_at));
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    #[test]
    fn test_ipv6_expiry_rules_preserve_ipv4_cache_behavior() {
        if IFACE_NEIGHBOR_CACHE_COUNT == 0 {
            return;
        }

        let mut cache = Cache::new();
        let first = crate::wire::Ipv4Address::new(192, 0, 2, 1);
        let second = crate::wire::Ipv4Address::new(192, 0, 2, 2);
        let t0 = Instant::from_secs(10);
        let expired_at = t0 + Cache::ENTRY_LIFETIME;

        cache.fill(first.into(), HADDR_A, t0);
        cache.reset_expiry_if_existing(first.into(), HADDR_A, expired_at);
        assert_eq!(
            cache.lookup(&first.into(), expired_at),
            Answer::Found(HADDR_A)
        );

        if IFACE_NEIGHBOR_CACHE_COUNT < 2 {
            return;
        }

        let mut cache = Cache::new();
        cache.fill(first.into(), HADDR_A, t0);
        cache.fill(second.into(), HADDR_B, t0);
        cache.fill(first.into(), HADDR_C, expired_at);

        // Updating an existing IPv4 entry stays in place, preserving the
        // original tie order used when the cache later needs an eviction.
        assert_eq!(
            cache.storage.iter().next().map(|(address, _)| *address),
            Some(first.into())
        );
    }

    #[cfg(feature = "proto-ipv6")]
    #[test]
    fn test_outbound_ndisc_probe_windows() {
        let mut cache = Cache::new();
        let t0 = Instant::from_secs(10);
        let t1 = t0 + Cache::SILENT_TIME;
        let t2 = t1 + Cache::SILENT_TIME;
        let t3 = t2 + Cache::SILENT_TIME;

        let mut abandoned_cache = Cache::new();
        abandoned_cache.record_neighbor_probe(MOCK_IP_ADDR_4, t0);
        assert!(abandoned_cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_4, t2));
        assert!(!abandoned_cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_4, t3));

        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t0);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t0));
        assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_2, t0));
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t1));

        if IFACE_NEIGHBOR_CACHE_COUNT >= 2 {
            cache.record_neighbor_probe(MOCK_IP_ADDR_2, t0);
            assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t0));
            assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_2, t0));
            // A completed resolution clears only the matching record.
            cache.fill(MOCK_IP_ADDR_2.into(), HADDR_A, t0);
            assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_2, t0));
            assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t0));
        }

        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t1);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t2));
        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t2);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t2 + Duration::from_millis(999)));
        assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t3));

        // A later solicitation starts a fresh resolution cycle.
        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t3);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t3));
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
}
