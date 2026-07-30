// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use heapless::LinearMap;
#[cfg(feature = "proto-ipv6-rio")]
use heapless::Vec;

#[cfg(feature = "proto-ipv6-rio")]
use crate::config::IFACE_MAX_ROUTE_COUNT;
use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;
use crate::time::{Duration, Instant};
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::Ipv6Address;
use crate::wire::{HardwareAddress, IpAddress};

#[cfg(feature = "proto-ipv6-rio")]
const MAX_RTR_PROBES: u8 = 3;

#[cfg(feature = "proto-ipv6-rio")]
const MAX_NEIGHBOR_PROBES: u8 = 3;

#[cfg(feature = "proto-ipv6-rio")]
const RTR_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(feature = "proto-ipv6-rio")]
const ROUTER_RESOLUTION_COUNT: usize = IFACE_MAX_ROUTE_COUNT;

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
    recovery_destination: Option<Ipv6Address>,
    recovery_probe_sent: bool,
    active: bool,
}

#[cfg(feature = "proto-ipv6-rio")]
impl RouterResolution {
    fn unreachable_at(&self) -> Instant {
        self.last_probe_at + Cache::SILENT_TIME
    }

    fn resolution_failure_at(&self) -> Instant {
        let remaining_windows = u32::from(MAX_RTR_PROBES.saturating_sub(self.probes_sent)) + 1;
        self.last_probe_at + Cache::SILENT_TIME * remaining_windows
    }

    fn resolution_is_outstanding(&self, now: Instant) -> bool {
        !self.recovery_probe_sent && self.last_probe_at <= now && now < self.resolution_failure_at()
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
            // Socket metadata already schedules the next useful address-
            // resolution attempt. Waking only this state after probes one or
            // two cannot send anything and needlessly wakes idle systems.
            RouterResolutionState::Pending if self.probes_sent < MAX_RTR_PROBES => None,
            RouterResolutionState::Pending => Some(self.unreachable_at()),
            RouterResolutionState::Unreachable if self.recovery_destination.is_some() => {
                Some(self.retry_at().max(now))
            }
            RouterResolutionState::Unreachable => None,
        }
    }
}

#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct NeighborResolution {
    probes_sent: u8,
    last_probe_at: Instant,
}

#[cfg(feature = "proto-ipv6-rio")]
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
    #[cfg(feature = "proto-ipv6-rio")]
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
    #[cfg(feature = "proto-ipv6-rio")]
    router_resolution: Vec<(Ipv6Address, RouterResolution), ROUTER_RESOLUTION_COUNT>,
    #[cfg(feature = "proto-ipv6-rio")]
    router_resolution_revision: u64,
    #[cfg(feature = "proto-ipv6-rio")]
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
            #[cfg(feature = "proto-ipv6-rio")]
            router_resolution: Vec::new(),
            #[cfg(feature = "proto-ipv6-rio")]
            router_resolution_revision: 0,
            #[cfg(feature = "proto-ipv6-rio")]
            neighbor_resolution: LinearMap::new(),
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn router_resolution_index(&self, address: &Ipv6Address) -> Result<usize, usize> {
        // Route selection can query one resolution for every retained RIO.
        // Keeping the fixed-capacity records sorted makes those lookups O(log N)
        // without restricting user-configurable capacities as a hash map would.
        self.router_resolution
            .binary_search_by_key(address, |(router, _)| *router)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn router_resolution(&self, address: &Ipv6Address) -> Option<&RouterResolution> {
        self.router_resolution_index(address)
            .ok()
            .map(|index| &self.router_resolution[index].1)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn router_resolution_mut(&mut self, address: &Ipv6Address) -> Option<&mut RouterResolution> {
        self.router_resolution_index(address)
            .ok()
            .map(|index| &mut self.router_resolution[index].1)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn clear_router_probe_context(&mut self, address: &Ipv6Address) {
        if let Some(resolution) = self.router_resolution_mut(address) {
            resolution.recovery_destination = None;
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn remove_router_resolution(&mut self, address: &Ipv6Address) {
        if let Ok(index) = self.router_resolution_index(address) {
            self.router_resolution.remove(index);
        }
    }

    /// Synchronize resolution records with learned routers in the public table.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn sync_router_resolutions(
        &mut self,
        routes_revision: u64,
        learned_routers: impl Iterator<Item = Ipv6Address>,
    ) {
        if self.router_resolution_revision == routes_revision {
            return;
        }
        self.router_resolution_revision = routes_revision;

        // A route change can invalidate the router itself. Retained recovery
        // destinations are revalidated immediately before egress, so an
        // unrelated revision must not discard the useful-traffic witness.
        // Marking active learned routers through logarithmic lookups permits
        // one linear prune without capacity-sized scratch.
        for (_, resolution) in &mut self.router_resolution {
            resolution.active = false;
        }
        for router in learned_routers {
            if let Some(resolution) = self.router_resolution_mut(&router) {
                resolution.active = true;
            }
        }
        self.router_resolution
            .retain(|(_, resolution)| resolution.active);
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
                #[cfg(feature = "proto-ipv6-rio")]
                {
                    match protocol_addr {
                        // An expired IPv6 entry is absent for RFC 4861
                        // IsRouter purposes. IPv4 retains the pre-RIO passive
                        // refresh behavior in dual-stack builds.
                        IpAddress::Ipv6(_) => timestamp < *expires_at,
                        #[cfg(feature = "proto-ipv4")]
                        IpAddress::Ipv4(_) => true,
                    }
                }
                #[cfg(not(feature = "proto-ipv6-rio"))]
                {
                    true
                }
            }
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
            // Any inbound packet can refresh this mapping, but RFC 4861
            // reachability requires a solicited NA or a real upper-layer hint.
            // Keep negative router state until that explicit confirmation.
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
        #[cfg(feature = "proto-ipv6-rio")]
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

        #[cfg(feature = "proto-ipv6-rio")]
        let is_router = self
            .storage
            .get(&protocol_addr)
            .is_some_and(|neighbor| neighbor.is_router);

        // Fills also come from unsolicited discovery traffic and static
        // cache maintenance, neither of which proves bidirectional reachability.
        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
            #[cfg(feature = "proto-ipv6-rio")]
            // Generic fills preserve explicit live IsRouter state. A newly
            // inserted mapping starts as a host until an RA/NA says otherwise.
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
        #[cfg(feature = "proto-ipv6-rio")]
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

    #[cfg(feature = "proto-ipv6-rio")]
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
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn fill_from_router_advertisement(
        &mut self,
        protocol_addr: Ipv6Address,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> bool {
        let mapping_created_or_changed =
            self.fill_ndisc_mapping(protocol_addr, hardware_addr, timestamp);
        let marked = self.set_router_if_live(&protocol_addr, true, timestamp);
        debug_assert!(marked.is_some(), "the RA mapping was just inserted");
        mapping_created_or_changed
    }

    /// Apply a valid Neighbor Solicitation mapping without inventing IsRouter.
    ///
    /// An existing live entry retains its flag; a new or expired entry starts
    /// with IsRouter FALSE. Returns whether the mapping was created or changed.
    #[cfg(feature = "proto-ipv6-rio")]
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
    /// the RFC 4861 TRUE-to-FALSE transition. Returns `None` when absent or
    /// expired.
    #[cfg(feature = "proto-ipv6-rio")]
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

    /// Return the prior IsRouter value of a live IPv6 Neighbor Cache entry.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn is_router(&self, protocol_addr: &Ipv6Address, timestamp: Instant) -> bool {
        self.storage
            .get(&IpAddress::Ipv6(*protocol_addr))
            .is_some_and(|neighbor| timestamp < neighbor.expires_at && neighbor.is_router)
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

    #[cfg(feature = "proto-ipv6-rio")]
    fn probe_is_outstanding(sent_at: Instant, now: Instant) -> bool {
        sent_at <= now && now < sent_at + Self::SILENT_TIME
    }

    /// Record an actually dispatched ordinary IPv6 Neighbor Solicitation.
    #[cfg(feature = "proto-ipv6-rio")]
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

    /// Return whether ordinary address resolution for this target is incomplete.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn neighbor_probe_outstanding(&self, address: &Ipv6Address, now: Instant) -> bool {
        self.neighbor_resolution
            .get(address)
            .is_some_and(|resolution| resolution.is_outstanding(now))
    }

    /// Record that a Neighbor Solicitation was sent to an IPv6 router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn record_router_probe(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.router_resolution_mut(&address) {
            if resolution.probes_sent < MAX_RTR_PROBES {
                if resolution.resolution_is_outstanding(now) {
                    resolution.probes_sent += 1;
                } else {
                    // An incomplete resolution cycle has a bounded synthetic
                    // lifetime. A much later NS starts a new cycle instead of
                    // inheriting probe attempts from abandoned traffic.
                    resolution.probes_sent = 1;
                }
                resolution.last_probe_at = now;
            }
            return;
        }

        let resolution = RouterResolution {
            probes_sent: 1,
            last_probe_at: now,
            recovery_destination: None,
            recovery_probe_sent: false,
            active: true,
        };

        let insertion_index = self
            .router_resolution_index(&address)
            .expect_err("new router resolution unexpectedly exists");
        // Resolution writes happen only when an NS is actually sent.
        // Paying the bounded shift here keeps the route-selection read path
        // sublinear without adding a second fixed-capacity index.
        if self
            .router_resolution
            .insert(insertion_index, (address, resolution))
            .is_err()
        {
            // Evicting a failed preferred router makes it Unknown and can
            // repeatedly divert traffic away from a reachable fallback. The
            // store is sized for every public learned route and stale records
            // are pruned on revision changes, so fullness is an invariant bug.
            debug_assert!(
                false,
                "router-resolution storage must cover all active learned routers"
            );
        }
    }

    /// Return whether router resolution or a recovery response is outstanding.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_probe_outstanding(&self, address: &Ipv6Address, now: Instant) -> bool {
        self.router_resolution(address).is_some_and(|resolution| {
            if resolution.recovery_probe_sent {
                // Recovery is a single throttled probe, not a new address-
                // resolution cycle, so it authorizes only its response window.
                Self::probe_is_outstanding(resolution.last_probe_at, now)
            } else {
                resolution.resolution_is_outstanding(now)
            }
        })
    }

    /// Record reachability confirmed by Neighbor Unreachability Detection.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn confirm_router_reachable(&mut self, address: &Ipv6Address) {
        // Learning or refreshing a link-layer mapping alone is not an
        // RFC 4861 reachability confirmation. Callers must invoke this only
        // for a validated solicited NA or a genuine upper-layer hint.
        self.remove_router_resolution(address);
    }

    /// Record an RFC 4861 transition from unreachable to STALE.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn mark_router_stale(&mut self, address: &Ipv6Address) {
        // An accepted unsolicited NA that changes the TLLA has not
        // confirmed bidirectional reachability, but STALE is also no longer
        // negative evidence. Removing only the resolution record represents
        // that distinction in this cache's simpler reachable/unknown model.
        self.remove_router_resolution(address);
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
        self.router_resolution(address)
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
    pub(crate) fn request_router_probe(
        &mut self,
        address: Ipv6Address,
        destination: Ipv6Address,
        now: Instant,
    ) -> bool {
        let Some(resolution) = self.router_resolution_mut(&address) else {
            return false;
        };
        if resolution.state(now) != RouterResolutionState::Unreachable {
            return false;
        }

        // There can be at most one useful-traffic witness per tracked
        // router. Co-locating it with the address-keyed resolution avoids a
        // second linear context lookup for every matching learned route.
        resolution.recovery_destination = Some(destination);
        true
    }

    /// Return a requested recovery probe that may be sent now.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_probe_required(&self, now: Instant) -> Option<Ipv6Address> {
        self.router_resolution
            .iter()
            .find_map(|(address, resolution)| {
                (resolution.state(now) == RouterResolutionState::Unreachable
                    && resolution.recovery_destination.is_some()
                    && now >= resolution.retry_at())
                .then_some(*address)
            })
    }

    /// Iterate over the useful-traffic context that requested this probe.
    ///
    /// At most one destination is retained for each router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_probe_destinations(
        &self,
        address: Ipv6Address,
    ) -> impl Iterator<Item = Ipv6Address> + '_ {
        self.router_resolution(&address)
            .and_then(|resolution| resolution.recovery_destination)
            .into_iter()
    }

    /// Cancel a recovery request while preserving negative reachability state.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn cancel_router_probe(&mut self, address: &Ipv6Address) {
        self.clear_router_probe_context(address);
    }

    /// Record a separately dispatched RFC 4191 recovery probe.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_recovery_probe_sent(&mut self, address: Ipv6Address, now: Instant) {
        if let Some(resolution) = self.router_resolution_mut(&address) {
            resolution.recovery_destination = None;
            resolution.probes_sent = MAX_RTR_PROBES;
            resolution.last_probe_at = now;
            resolution.recovery_probe_sent = true;
        }
    }

    /// Stop tracking a router that is no longer advertised.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn discard_router_resolution(&mut self, address: &Ipv6Address) {
        self.remove_router_resolution(address);
    }

    /// Return the next router-resolution state transition.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn router_resolution_poll_at(&self, now: Instant) -> Option<Instant> {
        self.router_resolution
            .iter()
            .filter_map(|(_, resolution)| resolution.poll_at(now))
            .min()
    }

    pub(crate) fn flush(&mut self) {
        self.storage.clear();
        #[cfg(feature = "proto-ipv6-rio")]
        {
            self.neighbor_resolution.clear();
            // Explicit address reconfiguration historically resets all
            // neighbor state. The automatic SLAAC path avoids calling flush
            // when it must preserve RA and NUD state across an internal update.
            self.router_resolution.clear();
        }
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

    #[cfg(feature = "proto-ipv6-rio")]
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

    #[cfg(feature = "proto-ipv6-rio")]
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

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6-rio"))]
    #[test]
    fn test_rio_expiry_rules_preserve_ipv4_cache_behavior() {
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
        // pre-RIO tie order used when the cache later needs an eviction.
        assert_eq!(
            cache.storage.iter().next().map(|(address, _)| *address),
            Some(first.into())
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
        #[cfg(feature = "proto-ipv6-rio")]
        {
            if ROUTER_RESOLUTION_COUNT != 0 {
                cache.record_router_probe(MOCK_IP_ADDR_1, Instant::ZERO);
            }
            cache.record_neighbor_probe(MOCK_IP_ADDR_2, Instant::ZERO);
        }
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
        #[cfg(feature = "proto-ipv6-rio")]
        {
            assert_eq!(
                cache.router_resolution_state(&MOCK_IP_ADDR_1, Instant::ZERO),
                RouterResolutionState::Unknown
            );
            assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_2, Instant::ZERO));
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
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
            cache.fill(MOCK_IP_ADDR_2.into(), HADDR_A, t0);
            assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_2, t0));
            assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t0));
        }

        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t1);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t2));
        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t2);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t2 + Duration::from_millis(999)));
        assert!(!cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t3));

        cache.record_neighbor_probe(MOCK_IP_ADDR_1, t3);
        assert!(cache.neighbor_probe_outstanding(&MOCK_IP_ADDR_1, t3));

        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

        let mut abandoned_router_cache = Cache::new();
        abandoned_router_cache.record_router_probe(MOCK_IP_ADDR_4, t0);
        assert!(abandoned_router_cache.router_probe_outstanding(&MOCK_IP_ADDR_4, t2));
        assert!(!abandoned_router_cache.router_probe_outstanding(&MOCK_IP_ADDR_4, t3));

        let mut restarted_router_cache = Cache::new();
        restarted_router_cache.record_router_probe(MOCK_IP_ADDR_4, t0);
        let restarted_at = t3 + Cache::SILENT_TIME;
        restarted_router_cache.record_router_probe(MOCK_IP_ADDR_4, restarted_at);
        restarted_router_cache
            .record_router_probe(MOCK_IP_ADDR_4, restarted_at + Cache::SILENT_TIME);
        assert_eq!(
            restarted_router_cache
                .router_resolution_state(&MOCK_IP_ADDR_4, restarted_at + Cache::SILENT_TIME * 2),
            RouterResolutionState::Pending
        );
        restarted_router_cache
            .record_router_probe(MOCK_IP_ADDR_4, restarted_at + Cache::SILENT_TIME * 2);
        assert_eq!(
            restarted_router_cache
                .router_resolution_state(&MOCK_IP_ADDR_4, restarted_at + Cache::SILENT_TIME * 3),
            RouterResolutionState::Unreachable
        );

        cache.record_router_probe(MOCK_IP_ADDR_3, t0);
        assert!(cache.router_probe_outstanding(&MOCK_IP_ADDR_3, t1));
        cache.record_router_probe(MOCK_IP_ADDR_3, t1);
        assert!(cache.router_probe_outstanding(&MOCK_IP_ADDR_3, t2));
        cache.record_router_probe(MOCK_IP_ADDR_3, t2);
        assert!(cache.router_probe_outstanding(&MOCK_IP_ADDR_3, t2 + Duration::from_millis(999)));
        assert!(cache.is_router_unreachable(&MOCK_IP_ADDR_3, t3));
        assert!(!cache.router_probe_outstanding(&MOCK_IP_ADDR_3, t3));

        let recovery_sent_at = t3 + Cache::SILENT_TIME;
        cache.router_recovery_probe_sent(MOCK_IP_ADDR_3, recovery_sent_at);
        assert!(cache.router_probe_outstanding(&MOCK_IP_ADDR_3, recovery_sent_at));
        assert!(
            !cache.router_probe_outstanding(&MOCK_IP_ADDR_3, recovery_sent_at + Cache::SILENT_TIME)
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolutions_keep_address_order() {
        if ROUTER_RESOLUTION_COUNT < 4 {
            return;
        }

        let mut cache = Cache::new();
        let routers = [
            MOCK_IP_ADDR_4,
            MOCK_IP_ADDR_2,
            MOCK_IP_ADDR_3,
            MOCK_IP_ADDR_1,
        ];
        let now = Instant::from_secs(10);
        for router in routers {
            cache.record_router_probe(router, now);
        }

        assert_eq!(cache.router_resolution.len(), routers.len());
        assert!(
            cache
                .router_resolution
                .windows(2)
                .all(|entries| entries[0].0 < entries[1].0)
        );
        for router in routers {
            assert_eq!(
                cache.router_resolution_state(&router, now),
                RouterResolutionState::Pending
            );
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_state() {
        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let destination = MOCK_IP_ADDR_2;
        let other_destination = MOCK_IP_ADDR_3;
        let t0 = Instant::from_secs(10);

        // A never-seen router has no negative reachability information.
        assert_eq!(
            cache.router_resolution_state(&router, t0),
            RouterResolutionState::Unknown
        );
        assert!(!cache.is_router_unreachable(&router, t0));

        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

        cache.record_router_probe(router, t0);
        assert_eq!(
            cache.router_resolution_state(&router, t0),
            RouterResolutionState::Pending
        );
        assert_eq!(cache.router_resolution_poll_at(t0), None);

        let t1 = t0 + Cache::SILENT_TIME;
        cache.record_router_probe(router, t1);
        assert_eq!(cache.router_resolution_poll_at(t1), None);
        let t2 = t1 + Cache::SILENT_TIME;
        cache.record_router_probe(router, t2);

        let unreachable_at = t2 + Cache::SILENT_TIME;
        assert_eq!(
            cache.router_resolution_state(&router, t2),
            RouterResolutionState::Pending
        );
        // The third probe has a real deadline: its timeout changes route
        // selection from Pending to Unreachable.
        assert_eq!(cache.router_resolution_poll_at(t2), Some(unreachable_at));
        assert!(cache.is_router_unreachable(&router, unreachable_at));

        let retry_at = unreachable_at + RTR_PROBE_RETRY_INTERVAL;
        assert_eq!(cache.router_resolution_poll_at(unreachable_at), None);
        cache.sync_router_resolutions(1, [router].into_iter());
        cache.request_router_probe(router, destination, unreachable_at);
        cache.request_router_probe(router, other_destination, unreachable_at);
        assert_eq!(
            cache.router_resolution_poll_at(unreachable_at),
            Some(retry_at)
        );
        assert_eq!(
            cache.router_resolution_state(&router, retry_at),
            RouterResolutionState::Unreachable
        );
        assert_eq!(cache.router_probe_required(retry_at), Some(router));
        assert_eq!(
            cache.router_probe_destinations(router).next(),
            Some(other_destination)
        );

        cache.router_recovery_probe_sent(router, retry_at);
        assert_eq!(
            cache.router_resolution_state(&router, retry_at),
            RouterResolutionState::Unreachable
        );
        assert_eq!(cache.router_resolution_poll_at(retry_at), None);
        cache.request_router_probe(router, destination, retry_at);
        assert_eq!(
            cache.router_resolution_poll_at(retry_at),
            Some(retry_at + RTR_PROBE_RETRY_INTERVAL)
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_probe_context_survives_unrelated_route_revision() {
        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);
        cache.record_router_probe(router, t0);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME * 2);
        let unreachable_at = t0 + Cache::SILENT_TIME * 3;
        let retry_at = unreachable_at + RTR_PROBE_RETRY_INTERVAL;

        cache.sync_router_resolutions(7, [router].into_iter());
        cache.request_router_probe(router, MOCK_IP_ADDR_2, unreachable_at);
        assert_eq!(cache.router_probe_required(retry_at), Some(router));

        cache.sync_router_resolutions(8, [router].into_iter());
        assert_eq!(
            cache.router_probe_destinations(router).next(),
            Some(MOCK_IP_ADDR_2)
        );
        assert_eq!(cache.router_probe_required(retry_at), Some(router));
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_route_revision_prunes_only_unlearned_router_resolutions() {
        if ROUTER_RESOLUTION_COUNT < 2 {
            return;
        }

        let mut cache = Cache::new();
        let removed_router = MOCK_IP_ADDR_1;
        let retained_router = MOCK_IP_ADDR_2;
        let t0 = Instant::from_secs(10);

        for router in [removed_router, retained_router] {
            cache.record_router_probe(router, t0);
            cache.record_router_probe(router, t0 + Cache::SILENT_TIME);
            cache.record_router_probe(router, t0 + Cache::SILENT_TIME * 2);
        }
        let unreachable_at = t0 + Cache::SILENT_TIME * 3;
        cache.sync_router_resolutions(1, [removed_router, retained_router].into_iter());
        cache.request_router_probe(removed_router, MOCK_IP_ADDR_3, unreachable_at);
        cache.request_router_probe(retained_router, MOCK_IP_ADDR_4, unreachable_at);

        cache.sync_router_resolutions(2, [retained_router].into_iter());

        assert_eq!(cache.router_resolution.len(), 1);
        assert_eq!(
            cache.router_resolution_state(&removed_router, unreachable_at),
            RouterResolutionState::Unknown
        );
        assert_eq!(
            cache.router_resolution_state(&retained_router, unreachable_at),
            RouterResolutionState::Unreachable
        );
        assert_eq!(
            cache.router_probe_destinations(retained_router).next(),
            Some(MOCK_IP_ADDR_4)
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_not_cleared_on_fill() {
        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

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
            RouterResolutionState::Unreachable
        );
        assert!(cache.is_router_unreachable(&router, unreachable_at));
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_not_cleared_on_neighbor_refresh() {
        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

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
            RouterResolutionState::Unreachable
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn test_router_resolution_cleared_only_on_confirmation() {
        if ROUTER_RESOLUTION_COUNT == 0 {
            return;
        }

        let mut cache = Cache::new();
        let router = MOCK_IP_ADDR_1;
        let t0 = Instant::from_secs(10);

        cache.record_router_probe(router, t0);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME);
        cache.record_router_probe(router, t0 + Cache::SILENT_TIME * 2);
        let unreachable_at = t0 + Cache::SILENT_TIME * 3;
        assert!(cache.is_router_unreachable(&router, unreachable_at));

        cache.confirm_router_reachable(&router);
        assert_eq!(
            cache.router_resolution_state(&router, unreachable_at),
            RouterResolutionState::Unknown
        );
    }
}
