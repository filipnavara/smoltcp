#![deny(missing_docs)]
#[cfg(feature = "proto-ipv6-rio")]
use core::cmp::{Ordering, Reverse};

use heapless::{LinearMap, Vec};

use crate::config::{IFACE_MAX_PREFIX_COUNT, IFACE_MAX_ROUTE_COUNT};
#[cfg(feature = "proto-ipv6-rio")]
use crate::iface::route::LearnedRoute;
#[cfg(feature = "proto-ipv6-rio")]
use crate::iface::{Route as InterfaceRoute, Routes};
use crate::time::{Duration, Instant};
use crate::wire::NdiscPrefixInfoFlags;
#[cfg(all(feature = "proto-ipv6-rio", test))]
use crate::wire::NdiscRouteInformation;
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::{IpAddress, NdiscRouteInformationList, NdiscRoutePreference};
use crate::wire::{Ipv6Address, Ipv6Cidr, NdiscPrefixInformation, ipv6::AddressExt};

const MAX_RTR_SOLICITATIONS: u8 = 3;
const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
const IPV6_DEFAULT: Ipv6Cidr = Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0);

#[cfg(feature = "proto-ipv6-rio")]
/// Maximum number of learned routes retained for RFC 4191 selection.
///
/// Learned candidates share the interface's documented route bound. A
/// resource limit must not become a hidden second routing table merely because
/// RIO selection needs to retain alternate routers.
pub(crate) const SLAAC_ROUTE_CANDIDATE_COUNT: usize = IFACE_MAX_ROUTE_COUNT;
#[cfg(not(feature = "proto-ipv6-rio"))]
const SLAAC_ROUTE_CANDIDATE_COUNT: usize = IFACE_MAX_ROUTE_COUNT;

#[cfg(feature = "proto-ipv6-rio")]
type RouteValidUntil = Option<Instant>;
#[cfg(not(feature = "proto-ipv6-rio"))]
type RouteValidUntil = Instant;

/// Router solicitation state machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Phase {
    Start,
    Discovering,
    Maintaining,
    None,
}

/// A prefix of addresses received via router advertisements
#[derive(Debug, Clone, Copy)]
pub(crate) struct Route {
    /// IPv6 cidr to route
    pub cidr: Ipv6Cidr,
    /// Router, origin of the advertisement
    pub via_router: Ipv6Address,
    /// Valid lifetime of the route.
    ///
    /// With RFC 4191 support, `None` represents the infinite-lifetime sentinel.
    pub valid_until: RouteValidUntil,
    /// Preference advertised for the route.
    #[cfg(feature = "proto-ipv6-rio")]
    pub preference: NdiscRoutePreference,
    /// Stable arrival order used to break equal-rank RFC 4191 ties.
    #[cfg(feature = "proto-ipv6-rio")]
    order: u32,
}

/// Result of merging configured and RFC 4191 routes for forwarding.
#[cfg(feature = "proto-ipv6-rio")]
#[derive(Clone, Copy)]
pub(crate) struct RouteSelection {
    /// Next hop selected for the packet.
    pub(crate) next_hop: Option<IpAddress>,
    selected: Option<SelectedRoute>,
    selected_is_unreachable: bool,
}

#[cfg(feature = "proto-ipv6-rio")]
#[derive(Clone, Copy)]
enum SelectedRoute {
    Configured(InterfaceRoute),
    Learned(LearnedRoute),
}

/// Info associated with a prefix
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrefixInfo {
    preferred_until: Instant,
    valid_until: Instant,
}

impl PrefixInfo {
    fn new(preferred_until: Instant, valid_until: Instant) -> Self {
        Self {
            preferred_until,
            valid_until,
        }
    }

    /// Derive the prefix information from the neighbor discovery option.
    pub(crate) fn from_prefix(prefix: &NdiscPrefixInformation, now: Instant) -> Self {
        let preferred_until = now + prefix.preferred_lifetime;
        let valid_until = now + prefix.valid_lifetime;

        Self::new(preferred_until, valid_until)
    }

    /// Get whether the prefix is still valid.
    pub(crate) fn is_valid(&self, now: Instant) -> bool {
        self.valid_until > now
    }
}

impl Route {
    /// Compare this route based on the prefix and the next hop router.
    #[cfg(any(test, not(feature = "proto-ipv6-rio")))]
    pub fn same_route(&self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) -> bool {
        self.cidr == *cidr && self.via_router == *via_router
    }

    /// Get whether the route is still valid.
    pub fn is_valid(&self, now: Instant) -> bool {
        #[cfg(feature = "proto-ipv6-rio")]
        {
            self.valid_until.is_none_or(|valid_until| valid_until > now)
        }
        #[cfg(not(feature = "proto-ipv6-rio"))]
        {
            self.valid_until > now
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn preference_rank(&self) -> i8 {
        self.preference.rank()
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn identity_cmp(&self, other: &Self) -> Ordering {
        (self.cidr, self.via_router).cmp(&(other.cidr, other.via_router))
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn is_withdrawn(&self) -> bool {
        // `take_route_order` rebases before this value can be assigned, so it
        // is available as an in-place tombstone without stealing an Instant
        // value that could be a legitimate lifetime deadline.
        self.order == u32::MAX
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn usefulness_cmp(&self, other: &Self) -> Ordering {
        (
            self.cidr.prefix_len(),
            self.preference_rank(),
            Reverse(self.order),
        )
            .cmp(&(
                other.cidr.prefix_len(),
                other.preference_rank(),
                Reverse(other.order),
            ))
    }
}

/// SLAAC runtime state
///
/// Tracks router solicitations and collects information from all received
/// router advertisements.
///
/// State must be synchronized with the IP addresses and routes in the `Interface`.
#[derive(Debug)]
pub struct Slaac {
    /// Set of prefixes received.
    prefix: LinearMap<Ipv6Cidr, PrefixInfo, IFACE_MAX_PREFIX_COUNT>,
    /// Set of routes received.
    routes: Vec<Route, SLAAC_ROUTE_CANDIDATE_COUNT>,
    /// Router discovery phase.
    phase: Phase,
    /// Signal for address and route updates.
    sync_required: bool,
    /// Time to next router solicitation.
    retry_rs_at: Instant,
    /// Number of solicitations emitted.
    num_solicitations: u8,
    /// Monotonic tie breaker for learned routes.
    #[cfg(feature = "proto-ipv6-rio")]
    next_route_order: u32,
}

impl Slaac {
    pub(super) fn new() -> Self {
        Self {
            prefix: LinearMap::new(),
            routes: Vec::new(),
            phase: Phase::Start,
            sync_required: false,
            retry_rs_at: Instant::from_millis(0),
            num_solicitations: MAX_RTR_SOLICITATIONS,
            #[cfg(feature = "proto-ipv6-rio")]
            next_route_order: 0,
        }
    }

    /// Get whether router advertisement information is updated.
    ///
    /// This flags whether new prefixes or routes have been received, or current prefixes and
    /// routes have expired.
    pub(crate) fn has_ra_update(&self) -> bool {
        self.sync_required
    }

    /// Get a reference to the map of prefixes stored.
    pub(crate) fn prefix(&self) -> &LinearMap<Ipv6Cidr, PrefixInfo, IFACE_MAX_PREFIX_COUNT> {
        &self.prefix
    }

    /// Get a reference to the set of routes stored.
    #[cfg(any(test, not(feature = "proto-ipv6-rio")))]
    pub(crate) fn routes(&self) -> &Vec<Route, SLAAC_ROUTE_CANDIDATE_COUNT> {
        &self.routes
    }

    /// Return the number of retained learned-route candidates.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn learned_route_count(&self) -> usize {
        self.routes.len()
    }

    /// Return one valid learned-route candidate for public-table reconciliation.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn learned_route_at(&self, index: usize, now: Instant) -> Option<LearnedRoute> {
        let route = *self.routes.get(index)?;
        route.is_valid(now).then_some(LearnedRoute {
            cidr: route.cidr,
            via_router: route.via_router,
            valid_until: route.valid_until,
            preference: route.preference,
            // Reconciliation temporarily reorders candidates by
            // usefulness, so the vector index cannot represent arrival order.
            order: route.order,
        })
    }

    /// Sort learned candidates from most to least useful.
    ///
    /// Public-route reconciliation can consume candidates in this order
    /// without allocating another capacity-sized collection. Call
    /// [`Self::restore_learned_route_identity_order`] before processing more
    /// advertisements.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn sort_learned_routes_by_usefulness(&mut self) {
        self.routes.sort_unstable_by(|left, right| {
            right
                .usefulness_cmp(left)
                .then_with(|| left.identity_cmp(right))
        });
    }

    /// Restore the identity order used by linear admission and lookup.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn restore_learned_route_identity_order(&mut self) {
        self.routes
            .sort_unstable_by(|left, right| left.identity_cmp(right));
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn take_route_order(&mut self) -> u32 {
        if self.next_route_order == u32::MAX {
            // An arrival counter must not wrap and make a new route look
            // older than retained routes. Rebase the bounded set while
            // preserving its relative arrival order.
            self.routes.sort_unstable_by_key(|route| route.order);
            let mut order = 0;
            for route in self.routes.iter_mut() {
                if !route.is_withdrawn() {
                    route.order = order;
                    order = order
                        .checked_add(1)
                        .expect("learned route capacity fits in u32");
                }
            }
            self.restore_learned_route_identity_order();
            self.next_route_order = order;
        }

        let order = self.next_route_order;
        self.next_route_order = order
            .checked_add(1)
            .expect("rebased learned route order must have room");
        order
    }

    /// Whether a prefix can name a destination reached through a router.
    #[cfg(feature = "proto-ipv6-rio")]
    fn is_routable_prefix(cidr: &Ipv6Cidr) -> bool {
        let address = cidr.address();
        // A zero-length prefix is the default route, whose address is the
        // unspecified address by construction.
        if cidr.prefix_len() == 0 {
            return true;
        }
        !address.is_link_local()
            && !address.is_loopback()
            && !address.is_unspecified()
            && !address.is_multicast()
    }

    fn add_prefix(&mut self, cidr: &Ipv6Cidr, prefix: &NdiscPrefixInformation, now: Instant) {
        if cidr.address().is_link_local() {
            return;
        }
        let prefix_info = PrefixInfo::from_prefix(prefix, now);
        if let Ok(old_info) = self.prefix.insert(*cidr, prefix_info)
            && old_info.is_none()
        {
            self.sync_required = true;
        }
    }

    fn expire_prefix(&mut self, cidr: &Ipv6Cidr) {
        if let Some(info) = self.prefix.get_mut(cidr) {
            info.valid_until = Instant::from_millis(0);
            info.preferred_until = Instant::from_millis(0);
            self.sync_required = true;
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn route_identity_index(
        &self,
        cidr: &Ipv6Cidr,
        via_router: &Ipv6Address,
    ) -> Result<usize, usize> {
        self.routes.binary_search_by(|candidate| {
            (candidate.cidr, candidate.via_router).cmp(&(*cidr, *via_router))
        })
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn insert_route_by_identity(&mut self, route: Route) {
        let index = self
            .route_identity_index(&route.cidr, &route.via_router)
            .expect_err("learned route identity must be unique");
        self.routes
            .insert(index, route)
            .expect("learned-route admission established a free slot");
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn remove_withdrawn_routes(&mut self) {
        self.routes.retain(|route| !route.is_withdrawn());
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn replace_route_by_identity(&mut self, index: usize, route: Route) {
        self.routes.remove(index);
        self.insert_route_by_identity(route);
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn less_useful_index(&self, current: Option<usize>, candidate: usize) -> Option<usize> {
        match current {
            Some(current)
                if self.routes[current].usefulness_cmp(&self.routes[candidate])
                    != Ordering::Greater =>
            {
                Some(current)
            }
            _ => Some(candidate),
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn full_route_victim(&self, incoming: &Route) -> Option<usize> {
        let mut prefix_present = false;
        let mut worst = None;
        let mut worst_coverage_preserving = None;
        let mut group_start = 0;

        while group_start < self.routes.len() {
            let group_cidr = self.routes[group_start].cidr;
            let mut group_end = group_start + 1;
            while group_end < self.routes.len() && self.routes[group_end].cidr == group_cidr {
                group_end += 1;
            }

            let is_incoming_prefix = group_cidr == incoming.cidr;
            prefix_present |= is_incoming_prefix;
            let group_is_redundant = group_end - group_start > 1;

            for index in group_start..group_end {
                worst = self.less_useful_index(worst, index);
                if group_is_redundant || is_incoming_prefix {
                    // Removing a member of a repeated group preserves its
                    // prefix. The incoming route likewise preserves its own
                    // prefix when replacing that group's only member.
                    worst_coverage_preserving =
                        self.less_useful_index(worst_coverage_preserving, index);
                }
            }
            group_start = group_end;
        }

        if let Some(victim) = worst_coverage_preserving {
            if !prefix_present {
                // A new prefix adds forwarding coverage, so it gets a
                // redundant slot before any covered prefix is discarded.
                return Some(victim);
            }

            // The incoming route is another path to an existing prefix. Keep
            // it only when it improves the least useful removable fallback.
            return (incoming.usefulness_cmp(&self.routes[victim]) == Ordering::Greater)
                .then_some(victim);
        }

        let victim = worst?;
        // With one route per prefix, admission must trade one coverage set for
        // another. RFC 4191 lookup usefulness decides whether that is a gain.
        (incoming.usefulness_cmp(&self.routes[victim]) == Ordering::Greater).then_some(victim)
    }

    fn add_route(
        &mut self,
        cidr: &Ipv6Cidr,
        router: &Ipv6Address,
        #[cfg(feature = "proto-ipv6-rio")] preference: NdiscRoutePreference,
        valid_until: RouteValidUntil,
    ) {
        #[cfg(feature = "proto-ipv6-rio")]
        if IFACE_MAX_ROUTE_COUNT == 0 {
            // A zero route capacity is an explicit request to disable route
            // storage. Do not retain hidden RFC 4191 candidates that could
            // still affect forwarding despite an empty public route table.
            return;
        }

        #[cfg(feature = "proto-ipv6-rio")]
        if let Ok(index) = self.route_identity_index(cidr, router) {
            let was_withdrawn = self.routes[index].is_withdrawn();
            let refreshed_order = was_withdrawn.then(|| self.take_route_order());
            let route = &mut self.routes[index];
            let changed =
                was_withdrawn || route.valid_until != valid_until || route.preference != preference;
            route.valid_until = valid_until;
            route.preference = preference;
            if let Some(order) = refreshed_order {
                // A withdrawal followed by a duplicate positive RIO is a new
                // arrival, matching the previous remove-then-insert flow.
                route.order = order;
            }
            if changed {
                // The RIO public mirror carries the learned expiry, so a
                // refresh must replace that exact owned entry.
                self.sync_required = true;
            }
            return;
        }

        #[cfg(not(feature = "proto-ipv6-rio"))]
        if let Some(route) = self.routes.iter_mut().find(|r| r.same_route(cidr, router)) {
            // The legacy mirror has no expiry metadata. Refreshing only this
            // internal deadline must not remove and reappend the public route,
            // which would change equal-prefix tie order.
            route.valid_until = valid_until;
            return;
        }

        #[cfg(feature = "proto-ipv6-rio")]
        if self.routes.iter().any(Route::is_withdrawn) {
            // Withdrawals stay as tombstones until the whole RA has been
            // scanned, avoiding one compaction per option. A later distinct
            // insertion needs those logical free slots now, so compact the
            // entire batch once before applying normal admission.
            self.remove_withdrawn_routes();
        }

        let route = Route {
            cidr: *cidr,
            via_router: *router,
            valid_until,
            #[cfg(feature = "proto-ipv6-rio")]
            preference,
            #[cfg(feature = "proto-ipv6-rio")]
            order: self.take_route_order(),
        };

        #[cfg(not(feature = "proto-ipv6-rio"))]
        {
            // Preserve the legacy notification even when bounded storage
            // rejects a newly advertised route. Existing callers synchronize
            // after every new-route attempt, not only successful insertions.
            let _ = self.routes.push(route);
            self.sync_required = true;
        }

        #[cfg(feature = "proto-ipv6-rio")]
        {
            if !self.routes.is_full() {
                // Every same-prefix router is a usable fallback. The
                // documented total route bound is the only limit while space
                // remains; a per-prefix cap would silently discard reachability.
                self.insert_route_by_identity(route);
                self.sync_required = true;
                return;
            }

            // Identity ordering makes equal-prefix routes adjacent, so this
            // admission scan detects redundant groups in O(C) time.
            if let Some(victim) = self.full_route_victim(&route) {
                self.replace_route_by_identity(victim, route);
                self.sync_required = true;
            } else {
                // RFC 4191 section 4 permits a single advertisement to carry
                // many Route Information Options, so a small
                // IFACE_MAX_ROUTE_COUNT can refuse routes the router expects
                // to be installed. Report it rather than dropping silently.
                net_debug!(
                    "SLAAC: learned route {} via {} refused, route table is full",
                    cidr,
                    router
                );
            }
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) -> bool {
        let Ok(index) = self.route_identity_index(cidr, via_router) else {
            return false;
        };
        if self.routes[index].is_withdrawn() {
            return false;
        }

        // Marking an exact binary-searched entry makes R withdrawals
        // O(R log C). `process_advertisement` compacts all marks in one O(C)
        // pass after later duplicate RIOs have had a chance to revive them.
        self.routes[index].order = u32::MAX;
        self.sync_required = true;
        true
    }

    #[cfg(not(feature = "proto-ipv6-rio"))]
    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) {
        for route in self.routes.iter_mut() {
            if route.same_route(cidr, via_router) {
                // Keep the legacy tombstone until synchronization so the
                // interface can identify which mirrored route to remove.
                route.valid_until = Instant::ZERO;
                self.sync_required = true;
            }
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn learned_route_is_valid(route: LearnedRoute, now: Instant) -> bool {
        route
            .valid_until
            .is_none_or(|valid_until| valid_until > now)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn learned_route_is_better(candidate: LearnedRoute, current: LearnedRoute) -> bool {
        let candidate_rank = (candidate.cidr.prefix_len(), candidate.preference.rank());
        let current_rank = (current.cidr.prefix_len(), current.preference.rank());
        candidate_rank > current_rank
            || (candidate_rank == current_rank && candidate.order < current.order)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn route_candidates<F>(
        routes: &Routes,
        destination: &Ipv6Address,
        now: Instant,
        mut is_unreachable: F,
    ) -> (
        Option<InterfaceRoute>,
        Option<LearnedRoute>,
        Option<LearnedRoute>,
    )
    where
        F: FnMut(&Ipv6Address) -> bool,
    {
        let destination = IpAddress::Ipv6(*destination);
        let mut configured = None;
        let mut best_learned = None;
        let mut best_reachable_learned = None;

        for route in routes.iter().filter(|route| {
            route.cidr.contains_addr(&destination)
                && route.expires_at.is_none_or(|expires_at| now <= expires_at)
        }) {
            let Some(learned) = routes.learned(route) else {
                // Match Routes::lookup's last-wins behavior for equal-prefix
                // configured entries. Learned entries are ranked separately.
                if configured.is_none_or(|current: InterfaceRoute| {
                    route.cidr.prefix_len() >= current.cidr.prefix_len()
                }) {
                    configured = Some(*route);
                }
                continue;
            };
            if !Self::learned_route_is_valid(learned, now) {
                continue;
            }

            if best_learned.is_none_or(|current| Self::learned_route_is_better(learned, current)) {
                best_learned = Some(learned);
            }
            if !is_unreachable(&learned.via_router)
                && best_reachable_learned
                    .is_none_or(|current| Self::learned_route_is_better(learned, current))
            {
                best_reachable_learned = Some(learned);
            }
        }

        (configured, best_learned, best_reachable_learned)
    }

    /// Select a route from the authoritative public route table.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn lookup_route<F>(
        &self,
        routes: &Routes,
        destination: &Ipv6Address,
        now: Instant,
        is_unreachable: F,
    ) -> RouteSelection
    where
        F: FnMut(&Ipv6Address) -> bool,
    {
        let (configured, best_learned, best_reachable_learned) =
            Self::route_candidates(routes, destination, now, is_unreachable);

        let selected_reachable = match (configured, best_reachable_learned) {
            (Some(configured), Some(learned))
                if learned.cidr.prefix_len() > configured.cidr.prefix_len() =>
            {
                Some(SelectedRoute::Learned(learned))
            }
            (Some(configured), _) => Some(SelectedRoute::Configured(configured)),
            (None, Some(learned)) => Some(SelectedRoute::Learned(learned)),
            (None, None) => None,
        };

        // An installed configured route is usable independently of
        // neighbor-unreachability state. Only fall back to an unreachable
        // learned router when the public table has no matching configured or
        // reachable learned entry.
        let selected_is_unreachable = selected_reachable.is_none() && best_learned.is_some();
        let selected = selected_reachable.or_else(|| best_learned.map(SelectedRoute::Learned));

        let next_hop = selected.map(|selected| match selected {
            SelectedRoute::Configured(route) => route.via_router,
            SelectedRoute::Learned(route) => route.via_router.into(),
        });
        RouteSelection {
            next_hop,
            selected,
            selected_is_unreachable,
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn is_recovery_probe_candidate(selection: RouteSelection, route: LearnedRoute) -> bool {
        let Some(selected) = selection.selected else {
            return false;
        };
        let (same_router, route_is_preferable) = match selected {
            SelectedRoute::Configured(selected) => (
                selected.via_router == route.via_router.into(),
                // A configured route intentionally wins an equal-prefix tie,
                // so only a longer learned prefix was skipped.
                route.cidr.prefix_len() > selected.cidr.prefix_len(),
            ),
            SelectedRoute::Learned(selected) => {
                let rank = (route.cidr.prefix_len(), route.preference.rank());
                let selected_rank = (selected.cidr.prefix_len(), selected.preference.rank());
                (
                    selected.via_router == route.via_router,
                    rank > selected_rank || (rank == selected_rank && route.order < selected.order),
                )
            }
        };
        !same_router && (selection.selected_is_unreachable || route_is_preferable)
    }

    /// Iterate over routes whose routers may need an RFC 4191 recovery probe.
    ///
    /// The caller filters by current reachability and coalesces repeated
    /// routers. Yielding one entry per matching route keeps this scan linear;
    /// de-duplicating here would rescan every earlier route on packet egress.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn recovery_probe_candidates<'a>(
        &'a self,
        routes: &'a Routes,
        destination: &Ipv6Address,
        now: Instant,
        selection: RouteSelection,
    ) -> impl Iterator<Item = Ipv6Address> + 'a {
        let destination = IpAddress::Ipv6(*destination);
        routes.iter().filter_map(move |route| {
            let learned = routes.learned(route)?;
            (Self::learned_route_is_valid(learned, now)
                    && route.cidr.contains_addr(&destination)
                    // Equal-ranked routes retain arrival order. An
                    // unreachable route before the selected fallback would
                    // have won if reachable and still needs a recovery probe.
                    && Self::is_recovery_probe_candidate(selection, learned))
            .then_some(learned.via_router)
        })
    }

    /// Invalidate every route through a node that is no longer a router.
    #[cfg(not(feature = "proto-ipv6-rio"))]
    pub(crate) fn remove_router(&mut self, address: &Ipv6Address) -> bool {
        let mut removed = false;
        for route in self.routes.iter_mut() {
            if route.via_router == *address && route.valid_until > Instant::from_millis(0) {
                route.valid_until = Instant::from_millis(0);
                self.sync_required = true;
                removed = true;
            }
        }
        removed
    }

    /// Remove every learned route through a node that is no longer a router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn remove_router(&mut self, address: &Ipv6Address) -> bool {
        let old_len = self.routes.len();
        self.routes.retain(|route| route.via_router != *address);
        let removed = self.routes.len() != old_len;
        if removed {
            // RFC 4861 requires routing decisions through a node to be
            // invalidated as soon as an accepted NA clears its Router flag.
            // Signal maintenance as a fallback even though the receive path
            // also reconciles immediately before any queued packet is sent.
            self.sync_required = true;
        }
        removed
    }

    /// Return whether an address is a valid learned router in the public table.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn is_router(&self, routes: &Routes, address: &Ipv6Address, now: Instant) -> bool {
        routes
            .iter()
            .filter_map(|route| routes.learned(route))
            .any(|route| Self::learned_route_is_valid(route, now) && route.via_router == *address)
    }

    fn process_prefix(&mut self, prefix: NdiscPrefixInformation, now: Instant) {
        if !prefix.flags.contains(NdiscPrefixInfoFlags::ADDRCONF) {
            return;
        }

        let cidr = Ipv6Cidr::new(prefix.prefix, prefix.prefix_len);

        if prefix.valid_lifetime > Duration::ZERO {
            self.add_prefix(&cidr, &prefix, now);
        } else {
            self.expire_prefix(&cidr);
        }
    }

    /// Process a router advertisement's information.
    pub(super) fn process_advertisement(
        &mut self,
        source: &Ipv6Address,
        router_lifetime: Duration, // default route lifetime
        #[cfg(feature = "proto-ipv6-rio")] router_preference: NdiscRoutePreference,
        prefix: Option<NdiscPrefixInformation>, // prefix info
        #[cfg(feature = "proto-ipv6-rio")] route_info: NdiscRouteInformationList<'_>, // route info
        now: Instant,
    ) {
        #[cfg(feature = "proto-ipv6-rio")]
        let mut has_withdrawn_routes = false;

        #[cfg(feature = "proto-ipv6-rio")]
        {
            let previous_route_count = self.routes.len();
            // Normal `poll()` performs maintenance before ingress, but users
            // of the split polling API may receive this RA first. Remove
            // expired candidates here so they cannot occupy admission slots
            // or preserve stale tie-breaking order for a refreshed route.
            self.routes.retain(|route| route.is_valid(now));
            if self.routes.len() != previous_route_count {
                self.sync_required = true;
            }
        }

        if let Some(prefix) = prefix
            && prefix.is_valid_prefix_info()
        {
            self.process_prefix(prefix, now)
        }

        if router_lifetime > Duration::ZERO {
            #[cfg(feature = "proto-ipv6-rio")]
            self.add_route(
                &IPV6_DEFAULT,
                source,
                router_preference,
                Some(now + router_lifetime),
            );
            #[cfg(not(feature = "proto-ipv6-rio"))]
            self.add_route(&IPV6_DEFAULT, source, now + router_lifetime);
        } else {
            #[cfg(feature = "proto-ipv6-rio")]
            {
                has_withdrawn_routes |= self.expire_route(&IPV6_DEFAULT, source);
            }
            #[cfg(not(feature = "proto-ipv6-rio"))]
            self.expire_route(&IPV6_DEFAULT, source);
        }

        #[cfg(feature = "proto-ipv6-rio")]
        for route_info in route_info.iter() {
            // Parsed lists lazily yield only wire-valid RIOs. Avoid repeating
            // wire-level policy in the SLAAC state machine.
            let cidr = Ipv6Cidr::new(route_info.prefix, route_info.prefix_len);
            if !Self::is_routable_prefix(&cidr) {
                // RFC 4191 section 3.1: a Route Information Option carries a
                // prefix reachable through the advertising router. Prefixes
                // that are never routed off-link, and the unspecified address,
                // cannot describe such a destination. Mirror the equivalent
                // Prefix Information Option filter instead of installing a
                // route that would divert on-link or invalid traffic.
                net_debug!("SLAAC: ignoring route information for prefix {}", cidr);
                continue;
            }
            if route_info.route_lifetime > Duration::ZERO {
                let valid_until = if route_info.has_infinite_lifetime() {
                    None
                } else {
                    Some(now + route_info.route_lifetime)
                };
                self.add_route(&cidr, source, route_info.preference, valid_until);
            } else {
                has_withdrawn_routes |= self.expire_route(&cidr, source);
            }
        }

        #[cfg(feature = "proto-ipv6-rio")]
        if has_withdrawn_routes {
            // One stable compaction avoids repeatedly shifting the bounded
            // identity-sorted vector for every withdrawn RIO in this RA.
            self.remove_withdrawn_routes();
        }

        // Advertisement might be unsolicited
        if self.phase == Phase::Discovering {
            self.phase = Phase::Maintaining;
        }
    }

    fn prefix_expire_sync_required(&self, now: Instant) -> bool {
        self.prefix.values().any(|info| !info.is_valid(now))
    }

    fn route_expire_sync_required(&self, now: Instant) -> bool {
        self.routes.iter().any(|r| !r.is_valid(now))
    }

    /// Get whether a route and prefix information must be synchronized with the interface.
    pub(crate) fn sync_required(&self, now: Instant) -> bool {
        self.has_ra_update()
            || self.prefix_expire_sync_required(now)
            || self.route_expire_sync_required(now)
    }

    /// Remove expired routes and prefixes.
    pub(crate) fn update_slaac_state(&mut self, now: Instant) {
        let removals: Vec<Ipv6Cidr, IFACE_MAX_PREFIX_COUNT> = self
            .prefix
            .iter()
            .filter_map(|(cidr, info)| {
                if info.is_valid(now) {
                    None
                } else {
                    Some(*cidr)
                }
            })
            .collect();
        for cidr in removals.iter() {
            self.prefix.remove(cidr);
        }
        self.routes.retain(|r| r.is_valid(now));
        self.sync_required = false;
    }

    /// Get whether a router solicitation must be emitted.
    pub(crate) fn rs_required(&self, now: Instant) -> bool {
        match self.phase {
            Phase::Start | Phase::Discovering
                if self.retry_rs_at <= now && self.num_solicitations > 0 =>
            {
                true
            }
            _ => false,
        }
    }

    /// Update router solicitation tracking state
    ///
    /// Must be called after sending a router solicitation on the interface.
    pub(crate) fn rs_sent(&mut self, now: Instant) {
        match self.phase {
            Phase::Start | Phase::Discovering if self.retry_rs_at <= now => {
                if self.num_solicitations == 0 {
                    self.phase = Phase::None;
                } else {
                    self.num_solicitations -= 1;
                    self.phase = Phase::Discovering;
                    self.retry_rs_at = now + RTR_SOLICITATION_INTERVAL;
                }
            }
            _ => (),
        }
    }

    /// Get the next time the SLAAC state must be polled for updates.
    pub(crate) fn poll_at(&self, now: Instant) -> Option<Instant> {
        #[cfg(feature = "proto-ipv6-rio")]
        if self.sync_required(now) {
            // A received RA changes forwarding state before any lifetime
            // deadline, so users of split polling must be woken immediately.
            return Some(now);
        }

        match self.phase {
            Phase::Discovering | Phase::Start => Some(self.retry_rs_at),
            Phase::Maintaining => {
                let prefix_at = self.prefix.values().filter_map(|prefix_info| {
                    if prefix_info.is_valid(now) {
                        Some(prefix_info.valid_until)
                    } else {
                        None
                    }
                });
                #[cfg(feature = "proto-ipv6-rio")]
                let routes_at = self
                    .routes
                    .iter()
                    .filter_map(|r| if r.is_valid(now) { r.valid_until } else { None });
                #[cfg(not(feature = "proto-ipv6-rio"))]
                let routes_at = self.routes.iter().filter_map(|r| {
                    // Legacy routes always have a finite deadline, so keep the
                    // compact Instant representation and its original timing.
                    r.is_valid(now).then_some(r.valid_until)
                });
                prefix_at.chain(routes_at).min()
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv6-rio")]
    use crate::wire::{
        Icmpv6Message, Icmpv6Packet, NdiscOption, NdiscOptionRepr, NdiscRepr, NdiscRouterFlags,
    };

    mod mock {
        use super::super::*;
        pub const SOURCE: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 0);
        #[cfg(feature = "proto-ipv6-rio")]
        pub const SOURCE_2: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 2);
        #[cfg(feature = "proto-ipv6-rio")]
        pub const SOURCE_3: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 3);
        pub const PREFIX: NdiscPrefixInformation = NdiscPrefixInformation {
            prefix_len: 64,
            flags: NdiscPrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(700),
            preferred_lifetime: Duration::from_secs(300),
            prefix: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        };
        pub const VALID: Duration = Duration::from_secs(600);

        pub const ROUTE: Route = Route {
            cidr: Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0),
            via_router: SOURCE,
            #[cfg(feature = "proto-ipv6-rio")]
            valid_until: Some(Instant::from_millis_const(100000)),
            #[cfg(not(feature = "proto-ipv6-rio"))]
            valid_until: Instant::from_millis_const(100000),
            #[cfg(feature = "proto-ipv6-rio")]
            preference: crate::wire::NdiscRoutePreference::Medium,
            #[cfg(feature = "proto-ipv6-rio")]
            order: 0,
        };

        #[cfg(feature = "proto-ipv6-rio")]
        pub const ROUTE_INFO: NdiscRouteInformation = NdiscRouteInformation {
            prefix_len: 64,
            preference: crate::wire::NdiscRoutePreference::High,
            route_lifetime: Duration::from_secs(1800),
            prefix: Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0),
        };
    }
    use mock::*;

    #[cfg(feature = "proto-ipv6-rio")]
    fn route_info_list(route: NdiscRouteInformation) -> NdiscRouteInformationList<'static> {
        NdiscRouteInformationList::try_from(route).unwrap()
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn parsed_route_info<'a>(
        bytes: &'a mut [u8],
        entries: &[NdiscRouteInformation],
    ) -> NdiscRouteInformationList<'a> {
        {
            let mut packet = Icmpv6Packet::new_unchecked(&mut *bytes);
            packet.set_msg_type(Icmpv6Message::RouterAdvert);
            packet.set_msg_code(0);
            packet.set_router_flags(NdiscRouterFlags::empty());
            packet.set_router_preference(NdiscRoutePreference::Medium);
            packet.set_router_lifetime(Duration::ZERO);

            let mut offset = 0;
            for entry in entries {
                let repr = NdiscOptionRepr::RouteInformation(*entry);
                let len = repr.buffer_len();
                let mut option =
                    NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..offset + len]);
                repr.emit(&mut option);
                offset += len;
            }
            assert_eq!(offset, packet.payload_mut().len());
        }

        let packet = Icmpv6Packet::new_unchecked(&*bytes);
        let NdiscRepr::RouterAdvert { route_info, .. } = NdiscRepr::parse(&packet).unwrap() else {
            panic!("expected router advertisement");
        };
        route_info
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn reconcile_routes(slaac: &mut Slaac, routes: &mut Routes, now: Instant) {
        // Production reconciliation admits the most useful candidates
        // first without allocating a second capacity-sized vector, then
        // restores the identity grouping required by advertisement admission.
        slaac.sort_learned_routes_by_usefulness();
        routes.reconcile_learned(slaac.learned_route_count(), |index| {
            slaac.learned_route_at(index, now)
        });
        slaac.restore_learned_route_identity_order();
    }

    #[test]
    fn test_route() {
        assert!(ROUTE.same_route(&Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0), &SOURCE));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 64), &SOURCE));
        assert!(!ROUTE.same_route(
            &Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0),
            &Ipv6Address::UNSPECIFIED
        ));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 0), &Ipv6Address::UNSPECIFIED));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 64), &Ipv6Address::UNSPECIFIED));
    }

    #[test]
    fn test_route_valid() {
        assert!(ROUTE.is_valid(Instant::ZERO));
        assert!(!ROUTE.is_valid(Instant::from_secs(200)));
    }

    #[test]
    fn test_solicitation() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);
        assert!(slaac.rs_required(now));

        slaac.rs_sent(now);
        assert_eq!(slaac.num_solicitations, 2);
        assert!(!slaac.rs_required(now));

        let next_poll = slaac.poll_at(now).unwrap();
        assert_eq!(next_poll, now + RTR_SOLICITATION_INTERVAL);

        let now = next_poll;
        assert!(slaac.rs_required(now));

        slaac.num_solicitations = 0;
        assert!(!slaac.rs_required(now));
        slaac.rs_sent(now);
        assert_eq!(slaac.phase, Phase::None);
        assert!(slaac.poll_at(now).is_none());
    }

    #[test]
    fn test_ra_state() {
        let mut slaac = Slaac::new();
        assert_eq!(slaac.phase, Phase::Start);
        let now = Instant::from_millis(1);
        assert!(!slaac.has_ra_update());

        // Unsolicited advertisement
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        assert_eq!(slaac.phase, Phase::Start);
        assert!(slaac.has_ra_update());

        let now = Instant::from_secs(300);
        slaac.rs_sent(now);
        assert_eq!(slaac.phase, Phase::Discovering);

        // Solicited advertisement
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        assert_eq!(slaac.phase, Phase::Maintaining);
        #[cfg(feature = "proto-ipv6-rio")]
        assert_eq!(slaac.poll_at(now), Some(now));
        #[cfg(not(feature = "proto-ipv6-rio"))]
        assert_eq!(slaac.poll_at(now), Some(now + VALID));

        for (prefix, info) in slaac.prefix() {
            assert_eq!(prefix.address(), PREFIX.prefix);
            assert_eq!(prefix.prefix_len(), PREFIX.prefix_len);
            assert_eq!(info.valid_until, now + PREFIX.valid_lifetime);
            assert_eq!(info.preferred_until, now + PREFIX.preferred_lifetime);
            assert!(info.is_valid(now));
        }

        for route in slaac.routes() {
            assert_eq!(route.cidr, Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0));
            assert_eq!(route.via_router, SOURCE);
            #[cfg(feature = "proto-ipv6-rio")]
            assert_eq!(route.valid_until, Some(now + VALID));
            #[cfg(not(feature = "proto-ipv6-rio"))]
            assert_eq!(route.valid_until, now + VALID);
            assert!(route.is_valid(now));
        }
        assert_eq!(slaac.prefix().len(), 1);
        assert_eq!(slaac.routes().len(), 1);
        assert!(slaac.sync_required(now));

        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));
        let poll_at = slaac.poll_at(now).unwrap();
        assert_eq!(poll_at, now + VALID);

        // Skip time until the route expires
        let now = poll_at;
        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix() {
            assert!(info.is_valid(now));
        }
        for route in slaac.routes() {
            assert!(!route.is_valid(now));
        }

        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));
        assert_eq!(slaac.routes().len(), 0);

        // Skip time until the prefix expires
        let poll_at = slaac.poll_at(now).unwrap();
        let now = poll_at;
        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix() {
            assert!(!info.is_valid(now));
        }
        #[cfg(feature = "proto-ipv6-rio")]
        {
            // RIO wakes split pollers immediately so route selection cannot
            // keep using an expired learned candidate.
            assert_eq!(slaac.poll_at(now), Some(now));
        }
        #[cfg(not(feature = "proto-ipv6-rio"))]
        {
            // Preserve the legacy feature-off contract: once every stored
            // deadline is expired, there is no later timer to report.
            assert_eq!(slaac.poll_at(now), None);
        }
        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));
        assert_eq!(slaac.routes().len(), 0);
        assert_eq!(slaac.prefix().len(), 0);

        // No state remaining, nothing to wait on
        assert!(slaac.poll_at(now).is_none());
    }

    #[test]
    fn test_ra_expire() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);
        slaac.rs_sent(now);
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );

        let now = Instant::from_secs(300);

        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix() {
            assert!(info.is_valid(now));
        }
        for route in slaac.routes() {
            assert!(route.is_valid(now));
        }
        slaac.update_slaac_state(now);

        let mut expire_prefix = PREFIX;
        expire_prefix.preferred_lifetime = Duration::ZERO;
        expire_prefix.valid_lifetime = Duration::ZERO;

        // Invalidate the prefix, but not the route
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(expire_prefix),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );

        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix() {
            assert!(!info.is_valid(now));
        }
        for route in slaac.routes() {
            assert!(route.is_valid(now));
        }
        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix().len(), 0);
        assert_eq!(slaac.routes().len(), 1);

        assert!(!slaac.sync_required(now));
        // Invalidate also the route
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRoutePreference::Medium,
            Some(expire_prefix),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        assert!(slaac.sync_required(now));
        #[cfg(feature = "proto-ipv6-rio")]
        {
            assert!(slaac.routes().is_empty());
            assert_eq!(slaac.poll_at(now), Some(now));
        }
        #[cfg(not(feature = "proto-ipv6-rio"))]
        {
            assert_eq!(slaac.routes().len(), 1);
            assert!(!slaac.routes()[0].is_valid(now));
            assert_eq!(slaac.poll_at(now), None);
        }

        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix().len(), 0);
        assert_eq!(slaac.routes().len(), 0);
        assert!(!slaac.sync_required(now));
        // No state remaining, nothing to wait on
        assert!(slaac.poll_at(now).is_none());
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_ra_route_info() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);
        slaac.rs_sent(now);
        let cidr = Ipv6Cidr::new(ROUTE_INFO.prefix, ROUTE_INFO.prefix_len);

        // RIO adds a route to the advertised prefix (alongside the default route)
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(ROUTE_INFO),
            now,
        );
        assert_eq!(slaac.routes().len(), 2);
        let route = slaac.routes().iter().find(|r| r.cidr == cidr).unwrap();
        assert_eq!(route.via_router, SOURCE);
        assert_eq!(route.valid_until, Some(now + ROUTE_INFO.route_lifetime));
        assert_eq!(route.preference, ROUTE_INFO.preference);
        assert!(route.is_valid(now));

        // A zero route lifetime expires only the RIO-learned route
        let mut expire = ROUTE_INFO;
        expire.route_lifetime = Duration::ZERO;
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(expire),
            now,
        );
        assert!(slaac.routes().iter().all(|route| route.cidr != cidr));
        assert!(
            slaac
                .routes()
                .iter()
                .find(|r| r.cidr == IPV6_DEFAULT)
                .unwrap()
                .is_valid(now)
        );

        slaac.update_slaac_state(now);
        assert_eq!(slaac.routes().len(), 1);
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_ra_ignores_unroutable_route_info_prefixes() {
        let now = Instant::from_millis(1);
        for (prefix, prefix_len) in [
            (Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64),
            (Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1), 128),
            (Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 64),
            (Ipv6Address::UNSPECIFIED, 64),
        ] {
            let mut slaac = Slaac::new();
            let mut info = ROUTE_INFO;
            info.prefix = prefix;
            info.prefix_len = prefix_len;
            slaac.process_advertisement(
                &SOURCE,
                Duration::ZERO,
                NdiscRoutePreference::Medium,
                None,
                route_info_list(info),
                now,
            );
            assert!(slaac.routes().is_empty(), "installed a route for {prefix}");
        }

        // A zero-length prefix is the RFC 4191 default route and stays valid.
        let mut slaac = Slaac::new();
        let mut info = ROUTE_INFO;
        info.prefix = Ipv6Address::UNSPECIFIED;
        info.prefix_len = 0;
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(info),
            now,
        );
        assert_eq!(slaac.routes().len(), 1);
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_ra_multiple_route_info() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);
        let mut second = ROUTE_INFO;
        second.prefix = Ipv6Address::new(0xfd00, 0xdb8, 1, 0, 0, 0, 0, 0);
        let route_info_entries = [ROUTE_INFO, second];
        let route_info =
            NdiscRouteInformationList::try_from(route_info_entries.as_slice()).unwrap();

        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            route_info,
            now,
        );

        // The RA header's default and both RIOs must fit simultaneously.
        assert_eq!(slaac.routes().len(), 3);
        assert!(
            slaac
                .routes()
                .iter()
                .any(|route| route.cidr.address() == ROUTE_INFO.prefix)
        );
        assert!(
            slaac
                .routes()
                .iter()
                .any(|route| route.cidr.address() == second.prefix)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_duplicate_route_info_preserves_sequential_semantics() {
        let now = Instant::from_millis(1);
        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut medium = ROUTE_INFO;
        medium.preference = NdiscRoutePreference::Medium;
        let mut slaac = Slaac::new();

        for source in [SOURCE, SOURCE_2] {
            slaac.process_advertisement(
                &source,
                Duration::ZERO,
                NdiscRoutePreference::Medium,
                None,
                route_info_list(medium),
                now,
            );
        }

        let mut withdrawn = medium;
        withdrawn.route_lifetime = Duration::ZERO;
        let mut bytes = [0; 48];
        let route_info = parsed_route_info(&mut bytes, &[withdrawn, medium]);
        assert_eq!(route_info.iter().count(), 2);
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info,
            now,
        );

        // The later positive duplicate revives the route as a new
        // arrival. The untouched equal-rank router must therefore win the
        // stable arrival-order tie.
        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        assert_eq!(
            slaac
                .lookup_route(&routes, &destination, now, |_| false)
                .next_hop,
            Some(SOURCE_2.into())
        );

        let mut bytes = [0; 48];
        let route_info = parsed_route_info(&mut bytes, &[medium, withdrawn]);
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info,
            now,
        );
        assert!(
            slaac
                .routes()
                .iter()
                .all(|route| route.via_router != SOURCE)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_withdrawal_batch_frees_capacity_for_later_options() {
        let now = Instant::from_millis(1);
        let valid_until = Some(now + VALID);
        let prefix = |index| Ipv6Address::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0);
        let route = |index, lifetime| NdiscRouteInformation {
            prefix_len: 64,
            preference: NdiscRoutePreference::Medium,
            route_lifetime: lifetime,
            prefix: prefix(index),
        };
        let mut slaac = Slaac::new();

        for index in 0..4 {
            slaac.add_route(
                &Ipv6Cidr::new(prefix(index), 64),
                &SOURCE,
                NdiscRoutePreference::Medium,
                valid_until,
            );
        }
        let entries = [
            route(0, Duration::ZERO),
            route(1, Duration::ZERO),
            route(4, VALID),
            route(5, VALID),
        ];
        let route_info = NdiscRouteInformationList::try_from(entries.as_slice()).unwrap();
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info,
            now,
        );

        assert_eq!(slaac.routes().len(), IFACE_MAX_ROUTE_COUNT);
        for index in [2, 3, 4, 5] {
            assert!(
                slaac
                    .routes()
                    .iter()
                    .any(|candidate| candidate.cidr.address() == prefix(index))
            );
        }
        assert!(
            slaac
                .routes()
                .windows(2)
                .all(|pair| pair[0].identity_cmp(&pair[1]) == Ordering::Less)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_advertisement_prunes_expired_candidates_before_admission() {
        if IFACE_MAX_ROUTE_COUNT == 0 {
            return;
        }

        let mut slaac = Slaac::new();
        let expired_at = Instant::from_secs(1);
        for index in 0..IFACE_MAX_ROUTE_COUNT {
            let address = Ipv6Address::new(
                0x2001,
                0xdb8,
                0,
                0,
                0,
                0,
                (index >> 16) as u16,
                index as u16,
            );
            slaac.add_route(
                &Ipv6Cidr::new(address, 128),
                &SOURCE,
                NdiscRoutePreference::High,
                Some(expired_at),
            );
        }
        assert!(slaac.routes().is_full());

        let now = Instant::from_secs(2);
        let fresh = NdiscRouteInformation {
            prefix_len: 1,
            preference: NdiscRoutePreference::Low,
            route_lifetime: Duration::from_secs(600),
            prefix: Ipv6Address::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
        };
        slaac.process_advertisement(
            &SOURCE_2,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(fresh),
            now,
        );

        // The fresh /1 is deliberately less useful than every expired /128.
        // It is retained because expired routes are no longer candidates.
        assert_eq!(slaac.routes().len(), 1);
        assert_eq!(slaac.routes()[0].cidr, Ipv6Cidr::new(fresh.prefix, 1));
        assert_eq!(slaac.routes()[0].via_router, SOURCE_2);
        assert_eq!(
            slaac.routes()[0].valid_until,
            Some(now + fresh.route_lifetime)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_default_route_info_overrides_header() {
        let now = Instant::from_millis(1);
        let route_info = NdiscRouteInformation {
            prefix_len: 0,
            prefix: Ipv6Address::UNSPECIFIED,
            preference: NdiscRoutePreference::High,
            route_lifetime: Duration::from_secs(1800),
        };
        let mut slaac = Slaac::new();

        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(route_info),
            now,
        );

        let route = slaac.routes().first().unwrap();
        assert_eq!(route.cidr, IPV6_DEFAULT);
        assert_eq!(route.valid_until, Some(now + route_info.route_lifetime));
        assert_eq!(route.preference, NdiscRoutePreference::High);

        let mut withdrawn = route_info;
        withdrawn.route_lifetime = Duration::ZERO;
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(withdrawn),
            now,
        );
        assert!(slaac.routes().is_empty());
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_header_default_route_preference() {
        let now = Instant::from_millis(1);
        let mut slaac = Slaac::new();

        slaac.process_advertisement(
            &SOURCE,
            VALID,
            NdiscRoutePreference::Low,
            None,
            NdiscRouteInformationList::new(),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_2,
            VALID,
            NdiscRoutePreference::High,
            None,
            NdiscRouteInformationList::new(),
            now,
        );

        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        let selection = slaac.lookup_route(
            &routes,
            &Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            now,
            |_| false,
        );
        assert_eq!(selection.next_hop, Some(SOURCE_2.into()));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_configured_route_wins_equal_prefix_but_not_longer_learned_prefix() {
        let now = Instant::from_millis(1);
        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let learned_cidr = Ipv6Cidr::new(ROUTE_INFO.prefix, ROUTE_INFO.prefix_len);
        let mut slaac = Slaac::new();
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(ROUTE_INFO),
            now,
        );

        let configured = |cidr: Ipv6Cidr| InterfaceRoute {
            cidr: cidr.into(),
            via_router: SOURCE_3.into(),
            preferred_until: None,
            expires_at: None,
        };

        let mut equal_routes = Routes::new();
        equal_routes.update(|storage| storage.push(configured(learned_cidr)).unwrap());
        reconcile_routes(&mut slaac, &mut equal_routes, now);
        assert_eq!(
            slaac
                .lookup_route(&equal_routes, &destination, now, |_| false)
                .next_hop,
            Some(SOURCE_3.into())
        );

        let mut less_specific_routes = Routes::new();
        less_specific_routes.update(|storage| {
            storage
                .push(configured(Ipv6Cidr::new(ROUTE_INFO.prefix, 48)))
                .unwrap()
        });
        reconcile_routes(&mut slaac, &mut less_specific_routes, now);
        assert_eq!(
            slaac
                .lookup_route(&less_specific_routes, &destination, now, |_| false)
                .next_hop,
            Some(SOURCE.into())
        );
        assert_eq!(
            slaac
                .lookup_route(&less_specific_routes, &destination, now, |router| {
                    *router == SOURCE
                })
                .next_hop,
            Some(SOURCE_3.into())
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_lookup_falls_back_and_recovers() {
        let now = Instant::from_millis(1);
        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;
        let mut slaac = Slaac::new();

        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(ROUTE_INFO),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_2,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(low),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_3,
            VALID,
            NdiscRoutePreference::Medium,
            None,
            NdiscRouteInformationList::new(),
            now,
        );

        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        let selection = |unreachable: &[Ipv6Address]| {
            slaac.lookup_route(&routes, &destination, now, |router| {
                unreachable.contains(router)
            })
        };
        assert_eq!(selection(&[]).next_hop, Some(SOURCE.into()));
        let fallback = selection(&[SOURCE]);
        assert_eq!(fallback.next_hop, Some(SOURCE_2.into()));
        let probes: Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT> = slaac
            .recovery_probe_candidates(&routes, &destination, now, fallback)
            .filter(|router| [SOURCE].contains(router))
            .collect();
        assert_eq!(probes.as_slice(), &[SOURCE]);

        let default = selection(&[SOURCE, SOURCE_2]);
        assert_eq!(default.next_hop, Some(SOURCE_3.into()));
        let probes: Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT> = slaac
            .recovery_probe_candidates(&routes, &destination, now, default)
            .filter(|router| [SOURCE, SOURCE_2].contains(router))
            .collect();
        assert_eq!(probes.as_slice(), &[SOURCE, SOURCE_2]);

        let all_unreachable = selection(&[SOURCE, SOURCE_2, SOURCE_3]);
        assert_eq!(all_unreachable.next_hop, Some(SOURCE.into()));
        let probes: Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT> = slaac
            .recovery_probe_candidates(&routes, &destination, now, all_unreachable)
            .filter(|router| [SOURCE, SOURCE_2, SOURCE_3].contains(router))
            .collect();
        assert_eq!(probes.as_slice(), &[SOURCE_2, SOURCE_3]);
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_equal_rank_recovery_preserves_selection_order() {
        let now = Instant::from_millis(1);
        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut slaac = Slaac::new();

        for source in [SOURCE, SOURCE_2] {
            slaac.process_advertisement(
                &source,
                Duration::ZERO,
                NdiscRoutePreference::Medium,
                None,
                route_info_list(ROUTE_INFO),
                now,
            );
        }

        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        let first_unreachable =
            slaac.lookup_route(&routes, &destination, now, |router| *router == SOURCE);
        assert_eq!(first_unreachable.next_hop, Some(SOURCE_2.into()));
        assert!(
            slaac
                .recovery_probe_candidates(&routes, &destination, now, first_unreachable)
                .eq([SOURCE])
        );

        let second_unreachable =
            slaac.lookup_route(&routes, &destination, now, |router| *router == SOURCE_2);
        assert_eq!(second_unreachable.next_hop, Some(SOURCE.into()));
        assert!(
            slaac
                .recovery_probe_candidates(&routes, &destination, now, second_unreachable)
                .next()
                .is_none()
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_candidate_capacity_keeps_three_router_fallbacks() {
        let now = Instant::from_millis(1);
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;
        let mut medium = ROUTE_INFO;
        medium.preference = NdiscRoutePreference::Medium;
        let mut slaac = Slaac::new();

        for (source, route) in [(SOURCE_3, ROUTE_INFO), (SOURCE, low), (SOURCE_2, medium)] {
            slaac.process_advertisement(
                &source,
                Duration::ZERO,
                NdiscRoutePreference::Medium,
                None,
                route_info_list(route),
                now,
            );
        }

        let cidr = Ipv6Cidr::new(ROUTE_INFO.prefix, ROUTE_INFO.prefix_len);
        let candidates: Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT> = slaac
            .routes()
            .iter()
            .filter(|route| route.cidr == cidr)
            .copied()
            .collect();
        // All three routers fit within the total route capacity. Keeping
        // only two would lose the final reachable fallback for this prefix.
        assert_eq!(candidates.len(), 3);

        assert!(
            slaac
                .routes()
                .windows(2)
                .all(|pair| pair[0].identity_cmp(&pair[1]) == Ordering::Less)
        );
        slaac.sort_learned_routes_by_usefulness();
        assert_eq!(
            slaac
                .routes()
                .iter()
                .map(|route| route.via_router)
                .collect::<Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT>>()
                .as_slice(),
            &[SOURCE_3, SOURCE_2, SOURCE]
        );
        assert_eq!(
            (0..3)
                .map(|index| slaac.learned_route_at(index, now).unwrap().order)
                .collect::<Vec<_, SLAAC_ROUTE_CANDIDATE_COUNT>>()
                .as_slice(),
            &[0, 2, 1]
        );
        slaac.restore_learned_route_identity_order();

        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        assert_eq!(
            slaac
                .lookup_route(&routes, &destination, now, |router| *router == SOURCE_3)
                .next_hop,
            Some(SOURCE_2.into())
        );
        assert_eq!(
            slaac
                .lookup_route(&routes, &destination, now, |router| {
                    [SOURCE_3, SOURCE_2].contains(router)
                })
                .next_hop,
            Some(SOURCE.into())
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_candidate_storage_respects_total_route_capacity() {
        assert_eq!(SLAAC_ROUTE_CANDIDATE_COUNT, IFACE_MAX_ROUTE_COUNT);

        let now = Instant::from_millis(1);
        let valid_until = Some(now + VALID);
        let prefix =
            |index| Ipv6Cidr::new(Ipv6Address::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0), 64);
        let source_4 = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 4);
        let mut slaac = Slaac::new();

        // Fill the explicit total bound while one prefix has a fallback.
        slaac.add_route(&prefix(1), &SOURCE, NdiscRoutePreference::Low, valid_until);
        slaac.add_route(
            &prefix(1),
            &SOURCE_2,
            NdiscRoutePreference::High,
            valid_until,
        );
        slaac.add_route(
            &prefix(2),
            &SOURCE_3,
            NdiscRoutePreference::Medium,
            valid_until,
        );
        slaac.add_route(
            &prefix(3),
            &source_4,
            NdiscRoutePreference::Medium,
            valid_until,
        );
        assert_eq!(slaac.routes().len(), IFACE_MAX_ROUTE_COUNT);

        // A new prefix adds coverage, so a bounded table should spend
        // the redundant slot before dropping any already covered prefix.
        slaac.add_route(&prefix(4), &SOURCE, NdiscRoutePreference::Low, valid_until);
        assert_eq!(slaac.routes().len(), IFACE_MAX_ROUTE_COUNT);
        for index in 1..=4 {
            assert!(
                slaac
                    .routes()
                    .iter()
                    .any(|route| route.cidr == prefix(index))
            );
        }
        assert!(
            slaac
                .routes()
                .iter()
                .all(|route| route.cidr != prefix(1) || route.via_router == SOURCE_2)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_full_candidate_storage_keeps_better_fallbacks() {
        let now = Instant::from_millis(1);
        let valid_until = Some(now + VALID);
        let prefix =
            |index| Ipv6Cidr::new(Ipv6Address::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0), 64);
        let source_4 = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 4);
        let source_5 = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 5);
        let source_6 = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 6);
        let mut slaac = Slaac::new();

        slaac.add_route(&prefix(1), &SOURCE, NdiscRoutePreference::Low, valid_until);
        slaac.add_route(
            &prefix(1),
            &SOURCE_2,
            NdiscRoutePreference::Medium,
            valid_until,
        );
        slaac.add_route(
            &prefix(2),
            &SOURCE_3,
            NdiscRoutePreference::Low,
            valid_until,
        );
        slaac.add_route(
            &prefix(3),
            &source_4,
            NdiscRoutePreference::Low,
            valid_until,
        );

        // A better same-prefix route replaces the least useful removable
        // fallback without reducing prefix coverage.
        slaac.add_route(
            &prefix(1),
            &source_5,
            NdiscRoutePreference::High,
            valid_until,
        );
        assert!(
            slaac
                .routes()
                .iter()
                .all(|route| route.via_router != SOURCE)
        );
        assert!(
            slaac
                .routes()
                .iter()
                .any(|route| route.via_router == source_5)
        );

        // A worse arrival cannot displace either retained fallback merely
        // because the table happens to be full.
        slaac.add_route(
            &prefix(1),
            &source_6,
            NdiscRoutePreference::Low,
            valid_until,
        );
        assert!(
            slaac
                .routes()
                .iter()
                .all(|route| route.via_router != source_6)
        );
        assert!(
            slaac
                .routes()
                .windows(2)
                .all(|pair| pair[0].identity_cmp(&pair[1]) == Ordering::Less)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_removed_public_learned_route_no_longer_affects_selection() {
        let now = Instant::from_millis(1);
        let mut slaac = Slaac::new();
        let destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;

        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(ROUTE_INFO),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_2,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(low),
            now,
        );

        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        assert_eq!(
            slaac
                .lookup_route(&routes, &destination, now, |_| false)
                .next_hop,
            Some(SOURCE.into())
        );

        routes.update(|storage| {
            let index = storage
                .iter()
                .position(|route| route.via_router == SOURCE.into())
                .unwrap();
            storage.remove(index);
        });

        // The public table is authoritative. A retained RA candidate
        // must not remain a hidden forwarding or router-recovery source after
        // the application removes its public learned entry.
        assert_eq!(
            slaac
                .lookup_route(&routes, &destination, now, |_| false)
                .next_hop,
            Some(SOURCE_2.into())
        );
        assert!(!slaac.is_router(&routes, &SOURCE, now));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_recovery_candidates_leave_router_coalescing_to_caller() {
        let now = Instant::from_millis(1);
        let destination = Ipv6Address::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
        let mut slaac = Slaac::new();
        let more_specific = Ipv6Cidr::new(Ipv6Address::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0), 64);
        let less_specific = Ipv6Cidr::new(Ipv6Address::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 48);

        slaac.add_route(
            &more_specific,
            &SOURCE,
            NdiscRoutePreference::High,
            Some(now + VALID),
        );
        slaac.add_route(
            &less_specific,
            &SOURCE,
            NdiscRoutePreference::High,
            Some(now + VALID),
        );
        slaac.add_route(
            &IPV6_DEFAULT,
            &SOURCE_2,
            NdiscRoutePreference::Medium,
            Some(now + VALID),
        );

        let mut routes = Routes::new();
        reconcile_routes(&mut slaac, &mut routes, now);
        let selection = slaac.lookup_route(&routes, &destination, now, |router| *router == SOURCE);
        assert_eq!(selection.next_hop, Some(SOURCE_2.into()));
        assert!(
            slaac
                .recovery_probe_candidates(&routes, &destination, now, selection)
                .eq([SOURCE, SOURCE])
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_infinite_route_lifetime() {
        let now = Instant::from_millis(1);
        let mut route_info = ROUTE_INFO;
        route_info.route_lifetime = NdiscRouteInformation::INFINITE_LIFETIME;
        let mut slaac = Slaac::new();

        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info_list(route_info),
            now,
        );

        let route = slaac.routes().first().unwrap();
        assert_eq!(route.valid_until, None);
        assert!(route.is_valid(Instant::from_secs(10_000_000_000_i64)));
    }

    #[test]
    #[cfg(not(feature = "proto-ipv6-rio"))]
    fn test_full_route_insertion_preserves_legacy_sync_notification() {
        let now = Instant::from_millis(1);
        let valid_until = now + VALID;
        let mut slaac = Slaac::new();

        for index in 0..IFACE_MAX_ROUTE_COUNT {
            let cidr = Ipv6Cidr::new(
                Ipv6Address::new(0x2001, 0xdb8, index as u16, 0, 0, 0, 0, 0),
                64,
            );
            slaac.add_route(&cidr, &SOURCE, valid_until);
        }
        slaac.update_slaac_state(now);
        assert!(!slaac.has_ra_update());

        let rejected = Ipv6Cidr::new(Ipv6Address::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 0), 64);
        slaac.add_route(&rejected, &SOURCE, valid_until);

        assert_eq!(slaac.routes().len(), IFACE_MAX_ROUTE_COUNT);
        assert!(!slaac.routes().iter().any(|route| route.cidr == rejected));
        assert!(slaac.has_ra_update());
    }
}
