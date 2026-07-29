#![deny(missing_docs)]
use heapless::{LinearMap, Vec};

use crate::config::{IFACE_MAX_PREFIX_COUNT, IFACE_MAX_ROUTE_COUNT};
#[cfg(feature = "proto-ipv6-rio")]
use crate::iface::Route as InterfaceRoute;
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

// One RA can contribute the header default plus the configured number of
// RIOs. Keeping two routers per prefix is the minimum bounded representation
// that can preserve RFC 4191 failover instead of discarding the first backup.
#[cfg(feature = "proto-ipv6-rio")]
const SLAAC_ROUTE_PREFIX_COUNT: usize = IFACE_MAX_ROUTE_COUNT + 1;
#[cfg(feature = "proto-ipv6-rio")]
const SLAAC_ROUTE_CANDIDATE_COUNT: usize = SLAAC_ROUTE_PREFIX_COUNT * 2;
#[cfg(not(feature = "proto-ipv6-rio"))]
const SLAAC_ROUTE_CANDIDATE_COUNT: usize = IFACE_MAX_ROUTE_COUNT;

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
    /// Valid lifetime of the route; `None` represents the RFC 4191 infinity
    /// sentinel.
    pub valid_until: Option<Instant>,
    /// Preference advertised for the route.
    #[cfg(feature = "proto-ipv6-rio")]
    pub preference: NdiscRoutePreference,
}

/// A route mirrored into the public interface route table by SLAAC.
///
/// Tracking ownership separately prevents a withdrawal from deleting a
/// matching route that was installed by the application.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InstalledRoute {
    pub cidr: Ipv6Cidr,
    pub via_router: Ipv6Address,
    pub valid_until: Option<Instant>,
}

/// Result of merging configured and RFC 4191 routes for forwarding.
#[cfg(feature = "proto-ipv6-rio")]
pub(crate) struct RouteSelection {
    /// Next hop selected for the packet.
    pub(crate) next_hop: Option<IpAddress>,
    /// Preferable unreachable routers that should receive recovery probes.
    pub(crate) skipped_routers: Vec<Ipv6Address, SLAAC_ROUTE_CANDIDATE_COUNT>,
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
    pub fn same_route(&self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) -> bool {
        self.cidr == *cidr && self.via_router == *via_router
    }

    /// Get whether the route is still valid.
    pub fn is_valid(&self, now: Instant) -> bool {
        self.valid_until.is_none_or(|valid_until| valid_until > now)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn preference_rank(&self) -> i8 {
        match self.preference {
            NdiscRoutePreference::Low => -1,
            NdiscRoutePreference::Medium => 0,
            NdiscRoutePreference::High => 1,
            NdiscRoutePreference::Unknown(_) => -2,
        }
    }

    #[cfg(not(feature = "proto-ipv6-rio"))]
    fn preference_rank(&self) -> i8 {
        0
    }

    /// Get whether this route should be synchronized to the interface.
    ///
    /// When identical prefixes are advertised by multiple routers, only
    /// routes with the highest advertised preference are active.
    #[cfg(all(test, feature = "proto-ipv6-rio"))]
    pub fn is_active(&self, routes: &[Route], now: Instant) -> bool {
        if !self.is_valid(now) {
            return false;
        }

        #[cfg(feature = "proto-ipv6-rio")]
        if routes.iter().any(|route| {
            route.is_valid(now)
                && route.cidr == self.cidr
                && route.preference_rank() > self.preference_rank()
        }) {
            return false;
        }

        #[cfg(not(feature = "proto-ipv6-rio"))]
        let _ = routes;

        true
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
    /// Routes currently mirrored into `Interface::routes`.
    installed_routes: Vec<InstalledRoute, IFACE_MAX_ROUTE_COUNT>,
    /// Router discovery phase.
    phase: Phase,
    /// Signal for address and route updates.
    sync_required: bool,
    /// Time to next router solicitation.
    retry_rs_at: Instant,
    /// Number of solicitations emitted.
    num_solicitations: u8,
}

impl Slaac {
    pub(super) fn new() -> Self {
        Self {
            prefix: LinearMap::new(),
            routes: Vec::new(),
            installed_routes: Vec::new(),
            phase: Phase::Start,
            sync_required: false,
            retry_rs_at: Instant::from_millis(0),
            num_solicitations: MAX_RTR_SOLICITATIONS,
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
    #[cfg(test)]
    pub(crate) fn routes(&self) -> &Vec<Route, SLAAC_ROUTE_CANDIDATE_COUNT> {
        &self.routes
    }

    /// Get the SLAAC-owned routes mirrored into the public route table.
    pub(crate) fn installed_routes(&self) -> &Vec<InstalledRoute, IFACE_MAX_ROUTE_COUNT> {
        &self.installed_routes
    }

    /// Replace the set of routes mirrored into the public route table.
    pub(crate) fn set_installed_routes(
        &mut self,
        installed_routes: Vec<InstalledRoute, IFACE_MAX_ROUTE_COUNT>,
    ) {
        self.installed_routes = installed_routes;
    }

    /// Return whether a public route is one previously installed by SLAAC.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn owns_interface_route(&self, route: &InterfaceRoute) -> bool {
        self.installed_routes.iter().any(|installed| {
            route.cidr == installed.cidr.into()
                && route.via_router == installed.via_router.into()
                && route.expires_at == installed.valid_until
        })
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

    fn add_route(
        &mut self,
        cidr: &Ipv6Cidr,
        router: &Ipv6Address,
        #[cfg(feature = "proto-ipv6-rio")] preference: NdiscRoutePreference,
        valid_until: Option<Instant>,
    ) {
        if IFACE_MAX_ROUTE_COUNT == 0 {
            // A zero route capacity is an explicit request to disable route
            // storage. Do not retain hidden RFC 4191 candidates that could
            // still affect forwarding despite an empty public route table.
            return;
        }

        if let Some(route) = self.routes.iter_mut().find(|r| r.same_route(cidr, router)) {
            #[cfg(feature = "proto-ipv6-rio")]
            let changed = route.valid_until != valid_until || route.preference != preference;
            #[cfg(not(feature = "proto-ipv6-rio"))]
            let changed = route.valid_until != valid_until;
            route.valid_until = valid_until;
            #[cfg(feature = "proto-ipv6-rio")]
            {
                route.preference = preference;
            }
            if changed {
                // The public mirror carries the learned expiry, so refreshing
                // a lifetime must replace that entry even when its next hop
                // and preference did not change.
                self.sync_required = true;
            }
            return;
        }

        let route = Route {
            cidr: *cidr,
            via_router: *router,
            valid_until,
            #[cfg(feature = "proto-ipv6-rio")]
            preference,
        };

        #[cfg(not(feature = "proto-ipv6-rio"))]
        if self.routes.push(route).is_ok() {
            self.sync_required = true;
        }

        #[cfg(feature = "proto-ipv6-rio")]
        {
            const ROUTERS_PER_PREFIX: usize = 2;

            let same_prefix_count = self
                .routes
                .iter()
                .filter(|candidate| candidate.cidr == *cidr)
                .count();

            if same_prefix_count == ROUTERS_PER_PREFIX {
                let worst = self
                    .routes
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| candidate.cidr == *cidr)
                    .min_by_key(|(_, candidate)| candidate.preference_rank())
                    .map(|(index, _)| index)
                    .unwrap();

                // A bounded table must retain the more useful fallback. Equal
                // preference keeps arrival order deterministic.
                if route.preference_rank() > self.routes[worst].preference_rank() {
                    self.routes[worst] = route;
                    self.sync_required = true;
                }
                return;
            }

            let prefix_is_known = same_prefix_count != 0;
            let prefix_count = self
                .routes
                .iter()
                .enumerate()
                .filter(|(index, candidate)| {
                    self.routes[..*index]
                        .iter()
                        .all(|earlier| earlier.cidr != candidate.cidr)
                })
                .count();

            if prefix_is_known || prefix_count < SLAAC_ROUTE_PREFIX_COUNT {
                self.routes
                    .push(route)
                    .expect("SLAAC candidate capacity matches its prefix policy");
                self.sync_required = true;
                return;
            }

            let worst_prefix = self
                .routes
                .iter()
                .enumerate()
                .filter(|(index, candidate)| {
                    self.routes[..*index]
                        .iter()
                        .all(|earlier| earlier.cidr != candidate.cidr)
                })
                .min_by(|(_, left), (_, right)| {
                    let left_rank = self
                        .routes
                        .iter()
                        .filter(|candidate| candidate.cidr == left.cidr)
                        .map(Route::preference_rank)
                        .max()
                        .unwrap();
                    let right_rank = self
                        .routes
                        .iter()
                        .filter(|candidate| candidate.cidr == right.cidr)
                        .map(Route::preference_rank)
                        .max()
                        .unwrap();
                    (left.cidr.prefix_len(), left_rank).cmp(&(right.cidr.prefix_len(), right_rank))
                })
                .map(|(_, route)| route.cidr)
                .unwrap();
            let worst_rank = self
                .routes
                .iter()
                .filter(|candidate| candidate.cidr == worst_prefix)
                .map(Route::preference_rank)
                .max()
                .unwrap();

            // Prefer retaining more-specific prefixes because RFC 4191 route
            // lookup ranks prefix length before preference.
            if (route.cidr.prefix_len(), route.preference_rank())
                > (worst_prefix.prefix_len(), worst_rank)
            {
                self.routes
                    .retain(|candidate| candidate.cidr != worst_prefix);
                self.routes
                    .push(route)
                    .expect("removing one prefix leaves candidate capacity");
                self.sync_required = true;
            }
        }
    }

    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) {
        let previous_len = self.routes.len();

        // Remove withdrawals immediately because `None` is reserved to mean
        // an infinite lifetime, not an expired candidate.
        self.routes
            .retain(|route| !route.same_route(cidr, via_router));
        if self.routes.len() != previous_len {
            self.sync_required = true;
        }
    }

    /// Select the bounded set mirrored into the public route table.
    pub(crate) fn selected_routes(&self, now: Instant) -> Vec<Route, IFACE_MAX_ROUTE_COUNT> {
        let mut selected: Vec<Route, IFACE_MAX_ROUTE_COUNT> = Vec::new();

        for route in self.routes.iter().filter(|route| route.is_valid(now)) {
            #[cfg(feature = "proto-ipv6-rio")]
            if let Some(existing) = selected
                .iter_mut()
                .find(|existing| existing.cidr == route.cidr)
            {
                if route.preference_rank() > existing.preference_rank() {
                    *existing = *route;
                }
                continue;
            }

            if selected.push(*route).is_ok() {
                continue;
            }

            let Some(worst) = selected
                .iter()
                .enumerate()
                .min_by_key(|(_, candidate)| {
                    (candidate.cidr.prefix_len(), candidate.preference_rank())
                })
                .map(|(index, _)| index)
            else {
                // `Vec<_, 0>` rejects every push. Keeping this branch benign
                // makes a zero configured route capacity mean "learn none".
                continue;
            };
            if (route.cidr.prefix_len(), route.preference_rank())
                > (
                    selected[worst].cidr.prefix_len(),
                    selected[worst].preference_rank(),
                )
            {
                selected[worst] = *route;
            }
        }

        // Synchronization tries the most useful entries first if application
        // routes leave fewer free slots than the configured SLAAC capacity.
        selected.sort_unstable_by(|left, right| {
            (right.cidr.prefix_len(), right.preference_rank())
                .cmp(&(left.cidr.prefix_len(), left.preference_rank()))
        });
        selected
    }

    /// Find the RFC 4191 route for a destination.
    #[cfg(all(feature = "proto-ipv6-rio", test))]
    pub(crate) fn lookup_route<F>(
        &self,
        destination: &Ipv6Address,
        now: Instant,
        is_unreachable: F,
    ) -> Option<Route>
    where
        F: FnMut(&Ipv6Address) -> bool,
    {
        let (best, best_reachable, _) = self.route_candidates(destination, now, is_unreachable);
        best_reachable.or(best)
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn route_candidates<F>(
        &self,
        destination: &Ipv6Address,
        now: Instant,
        mut is_unreachable: F,
    ) -> (
        Option<Route>,
        Option<Route>,
        Vec<Route, SLAAC_ROUTE_CANDIDATE_COUNT>,
    )
    where
        F: FnMut(&Ipv6Address) -> bool,
    {
        if IFACE_MAX_ROUTE_COUNT == 0 {
            return (None, None, Vec::new());
        }

        let mut best = None;
        let mut best_reachable = None;
        let mut unreachable_routes = Vec::new();

        for route in self
            .routes
            .iter()
            .filter(|route| route.is_valid(now) && route.cidr.contains_addr(destination))
        {
            let better_than = |current: Option<Route>| {
                current.is_none_or(|current| {
                    (route.cidr.prefix_len(), route.preference_rank())
                        > (current.cidr.prefix_len(), current.preference_rank())
                })
            };

            if better_than(best) {
                best = Some(*route);
            }
            if is_unreachable(&route.via_router) {
                unreachable_routes
                    .push(*route)
                    .expect("matching routes are bounded by route candidates");
            } else if better_than(best_reachable) {
                best_reachable = Some(*route);
            }
        }

        (best, best_reachable, unreachable_routes)
    }

    /// Merge a configured route with learned routes and identify recovery probes.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn lookup_route_with_configured<F>(
        &self,
        destination: &Ipv6Address,
        now: Instant,
        configured: Option<InterfaceRoute>,
        mut is_unreachable: F,
    ) -> RouteSelection
    where
        F: FnMut(&Ipv6Address) -> bool,
    {
        #[derive(Clone, Copy)]
        enum Candidate {
            Configured(InterfaceRoute),
            Advertised(Route),
        }

        fn choose(
            configured: Option<InterfaceRoute>,
            advertised: Option<Route>,
        ) -> Option<Candidate> {
            match (configured, advertised) {
                (Some(configured), Some(advertised))
                    if advertised.cidr.prefix_len() > configured.cidr.prefix_len() =>
                {
                    Some(Candidate::Advertised(advertised))
                }
                (Some(configured), _) => Some(Candidate::Configured(configured)),
                (None, Some(advertised)) => Some(Candidate::Advertised(advertised)),
                (None, None) => None,
            }
        }

        let (best, best_reachable, unreachable_routes) =
            self.route_candidates(destination, now, &mut is_unreachable);

        // Configured routes must take part before the all-unreachable fallback
        // is chosen. Otherwise an unreachable learned /64 could incorrectly
        // hide a usable configured default route. They remain administrator-
        // owned and are not suppressed by learned-router reachability state.
        let selected_reachable = choose(configured, best_reachable);
        let selected_is_unreachable = selected_reachable.is_none();
        let selected = selected_reachable.or_else(|| choose(configured, best));
        let mut skipped_routers = Vec::new();

        if let Some(selected) = selected {
            for route in unreachable_routes {
                let (same_router, route_is_preferable) = match selected {
                    Candidate::Configured(selected) => (
                        selected.via_router == route.via_router.into(),
                        // A configured route intentionally wins an equal-prefix
                        // tie, so only a longer learned prefix was skipped.
                        route.cidr.prefix_len() > selected.cidr.prefix_len(),
                    ),
                    Candidate::Advertised(selected) => (
                        selected.via_router == route.via_router,
                        (route.cidr.prefix_len(), route.preference_rank())
                            > (selected.cidr.prefix_len(), selected.preference_rank()),
                    ),
                };
                if !same_router
                    && (selected_is_unreachable || route_is_preferable)
                    && !skipped_routers.contains(&route.via_router)
                {
                    skipped_routers
                        .push(route.via_router)
                        .expect("skipped routers are bounded by route candidates");
                }
            }
        }

        let next_hop = selected.map(|selected| match selected {
            Candidate::Configured(route) => route.via_router,
            Candidate::Advertised(route) => route.via_router.into(),
        });
        RouteSelection {
            next_hop,
            skipped_routers,
        }
    }

    /// Return whether an address is a currently valid learned router.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn is_router(&self, address: &Ipv6Address, now: Instant) -> bool {
        self.routes
            .iter()
            .any(|route| route.is_valid(now) && route.via_router == *address)
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
        #[cfg(feature = "proto-ipv6-rio")] route_info: NdiscRouteInformationList, // route info
        now: Instant,
    ) {
        if let Some(prefix) = prefix
            && prefix.is_valid_prefix_info()
        {
            self.process_prefix(prefix, now)
        }

        if router_lifetime > Duration::ZERO {
            self.add_route(
                &IPV6_DEFAULT,
                source,
                #[cfg(feature = "proto-ipv6-rio")]
                router_preference,
                Some(now + router_lifetime),
            );
        } else {
            self.expire_route(&IPV6_DEFAULT, source);
        }

        #[cfg(feature = "proto-ipv6-rio")]
        for route_info in route_info
            .iter()
            .filter(|route_info| route_info.is_valid_route_info())
        {
            let cidr = Ipv6Cidr::new(route_info.prefix, route_info.prefix_len);
            if route_info.route_lifetime > Duration::ZERO {
                let valid_until = if route_info.has_infinite_lifetime() {
                    None
                } else {
                    Some(now + route_info.route_lifetime)
                };
                self.add_route(&cidr, source, route_info.preference, valid_until);
            } else {
                self.expire_route(&cidr, source);
            }
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
                let routes_at = self
                    .routes
                    .iter()
                    .filter_map(|r| if r.is_valid(now) { r.valid_until } else { None });
                prefix_at.chain(routes_at).min()
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
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
            valid_until: Some(Instant::from_millis_const(100000)),
            #[cfg(feature = "proto-ipv6-rio")]
            preference: crate::wire::NdiscRoutePreference::Medium,
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
        assert_eq!(slaac.poll_at(now), Some(now));

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
            assert_eq!(route.valid_until, Some(now + VALID));
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
        // Expiry itself is an immediate synchronization deadline.
        assert_eq!(slaac.poll_at(now), Some(now));
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
        assert!(slaac.routes().is_empty());
        assert_eq!(slaac.poll_at(now), Some(now));

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
            ROUTE_INFO.into(),
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
            expire.into(),
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
    fn test_ra_multiple_route_info() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);
        let mut second = ROUTE_INFO;
        second.prefix = Ipv6Address::new(0xfd00, 0xdb8, 1, 0, 0, 0, 0, 0);
        let mut route_info = NdiscRouteInformationList::from(ROUTE_INFO);
        route_info.push(second).unwrap();

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
            route_info.into(),
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
            withdrawn.into(),
            now,
        );
        assert!(slaac.routes().is_empty());
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_route_preference_selects_best_router() {
        let now = Instant::from_millis(1);
        let mut slaac = Slaac::new();
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;

        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            ROUTE_INFO.into(),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_2,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            low.into(),
            now,
        );

        let high_route = slaac
            .routes()
            .iter()
            .find(|route| route.via_router == SOURCE)
            .unwrap();
        let low_route = slaac
            .routes()
            .iter()
            .find(|route| route.via_router == SOURCE_2)
            .unwrap();
        assert!(high_route.is_active(slaac.routes().as_slice(), now));
        assert!(!low_route.is_active(slaac.routes().as_slice(), now));
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

        let selected = slaac.selected_routes(now);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].via_router, SOURCE_2);
        assert_eq!(selected[0].preference, NdiscRoutePreference::High);
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
            ROUTE_INFO.into(),
            now,
        );
        slaac.process_advertisement(
            &SOURCE_2,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            low.into(),
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

        let lookup = |unreachable: &[Ipv6Address]| {
            slaac
                .lookup_route(&destination, now, |router| unreachable.contains(router))
                .unwrap()
                .via_router
        };
        assert_eq!(lookup(&[]), SOURCE);
        assert_eq!(lookup(&[SOURCE]), SOURCE_2);
        assert_eq!(lookup(&[SOURCE, SOURCE_2]), SOURCE_3);
        assert_eq!(lookup(&[SOURCE, SOURCE_2, SOURCE_3]), SOURCE);
        assert_eq!(lookup(&[]), SOURCE);

        let selection = |unreachable: &[Ipv6Address]| {
            slaac.lookup_route_with_configured(&destination, now, None, |router| {
                unreachable.contains(router)
            })
        };
        let fallback = selection(&[SOURCE]);
        assert_eq!(fallback.next_hop, Some(SOURCE_2.into()));
        assert_eq!(fallback.skipped_routers.as_slice(), &[SOURCE]);

        let default = selection(&[SOURCE, SOURCE_2]);
        assert_eq!(default.next_hop, Some(SOURCE_3.into()));
        assert_eq!(default.skipped_routers.as_slice(), &[SOURCE, SOURCE_2]);

        let all_unreachable = selection(&[SOURCE, SOURCE_2, SOURCE_3]);
        assert_eq!(all_unreachable.next_hop, Some(SOURCE.into()));
        assert_eq!(
            all_unreachable.skipped_routers.as_slice(),
            &[SOURCE_2, SOURCE_3]
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_candidate_capacity_keeps_better_backup() {
        let now = Instant::from_millis(1);
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;
        let mut medium = ROUTE_INFO;
        medium.preference = NdiscRoutePreference::Medium;
        let mut slaac = Slaac::new();

        for (source, route) in [(SOURCE, low), (SOURCE_2, medium), (SOURCE_3, ROUTE_INFO)] {
            slaac.process_advertisement(
                &source,
                Duration::ZERO,
                NdiscRoutePreference::Medium,
                None,
                route.into(),
                now,
            );
        }

        let cidr = Ipv6Cidr::new(ROUTE_INFO.prefix, ROUTE_INFO.prefix_len);
        let candidates: Vec<_, 2> = slaac
            .routes()
            .iter()
            .filter(|route| route.cidr == cidr)
            .copied()
            .collect();
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|route| route.via_router != SOURCE));
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
            route_info.into(),
            now,
        );

        let route = slaac.routes().first().unwrap();
        assert_eq!(route.valid_until, None);
        assert!(route.is_valid(Instant::from_secs(10_000_000_000_i64)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_ra_route_info_reserved_preference() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);

        // Options with the reserved preference must be ignored (RFC 4191)
        let mut reserved = ROUTE_INFO;
        reserved.preference = crate::wire::NdiscRoutePreference::Unknown(2);
        let mut route_info = NdiscRouteInformationList::new();
        assert_eq!(route_info.push(reserved), Err(reserved));
        slaac.process_advertisement(
            &SOURCE,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info,
            now,
        );
        assert!(slaac.routes().is_empty());
        assert!(!slaac.sync_required(now));
    }
}
