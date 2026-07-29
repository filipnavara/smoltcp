#![deny(missing_docs)]
use heapless::{LinearMap, Vec};

use crate::config::{IFACE_MAX_PREFIX_COUNT, IFACE_MAX_ROUTE_COUNT};
use crate::time::{Duration, Instant};
use crate::wire::NdiscPrefixInfoFlags;
#[cfg(all(feature = "proto-ipv6-rio", test))]
use crate::wire::NdiscRouteInformation;
use crate::wire::{Ipv6Address, Ipv6Cidr, NdiscPrefixInformation, ipv6::AddressExt};
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::{NdiscRouteInformationList, NdiscRoutePreference};

const MAX_RTR_SOLICITATIONS: u8 = 3;
const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
const IPV6_DEFAULT: Ipv6Cidr = Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0);

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
    /// Valid lifetime of the route
    pub valid_until: Instant,
    /// Preference advertised for the route.
    #[cfg(feature = "proto-ipv6-rio")]
    pub preference: NdiscRoutePreference,
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
        self.valid_until > now
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

    /// Get whether this route should be synchronized to the interface.
    ///
    /// When identical prefixes are advertised by multiple routers, only
    /// routes with the highest advertised preference are active.
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
    routes: Vec<Route, IFACE_MAX_ROUTE_COUNT>,
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
    pub(crate) fn routes(&self) -> &Vec<Route, IFACE_MAX_ROUTE_COUNT> {
        &self.routes
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
        valid_until: Instant,
    ) {
        if let Some(route) = self.routes.iter_mut().find(|r| r.same_route(cidr, router)) {
            route.valid_until = valid_until;
            #[cfg(feature = "proto-ipv6-rio")]
            if route.preference != preference {
                route.preference = preference;
                self.sync_required = true;
            }
        } else {
            let _ = self.routes.push(Route {
                cidr: *cidr,
                via_router: *router,
                valid_until,
                #[cfg(feature = "proto-ipv6-rio")]
                preference,
            });
            self.sync_required = true;
        }
    }

    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) {
        for route in self.routes.iter_mut() {
            if route.same_route(cidr, via_router) {
                route.valid_until = Instant::from_millis(0);
                self.sync_required = true;
            }
        }
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
        router_lifetime: Duration,              // default route lifetime
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
                NdiscRoutePreference::Medium,
                now + router_lifetime,
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
                self.add_route(
                    &cidr,
                    source,
                    route_info.preference,
                    now + route_info.route_lifetime,
                );
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
                let routes_at = self.routes.iter().filter_map(|r| {
                    if r.is_valid(now) {
                        Some(r.valid_until)
                    } else {
                        None
                    }
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
    mod mock {
        use super::super::*;
        pub const SOURCE: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 0);
        #[cfg(feature = "proto-ipv6-rio")]
        pub const SOURCE_2: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 2);
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
            valid_until: Instant::from_millis_const(100000),
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
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        slaac.process_advertisement(
            &SOURCE,
            VALID,
            Some(PREFIX),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        assert_eq!(slaac.phase, Phase::Maintaining);
        let poll_at = slaac.poll_at(now).unwrap();
        assert_eq!(poll_at, now + VALID);

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
            assert_eq!(route.valid_until, now + VALID);
            assert!(route.is_valid(now));
        }
        assert_eq!(slaac.prefix().len(), 1);
        assert_eq!(slaac.routes().len(), 1);
        assert!(slaac.sync_required(now));

        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));

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
        // Should already return None
        assert!(slaac.poll_at(now).is_none());
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
            Some(expire_prefix),
            #[cfg(feature = "proto-ipv6-rio")]
            NdiscRouteInformationList::new(),
            now,
        );
        assert!(slaac.sync_required(now));
        for route in slaac.routes() {
            assert!(!route.is_valid(now));
        }
        assert!(slaac.poll_at(now).is_none());

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
        slaac.process_advertisement(&SOURCE, VALID, None, ROUTE_INFO.into(), now);
        assert_eq!(slaac.routes().len(), 2);
        let route = slaac.routes().iter().find(|r| r.cidr == cidr).unwrap();
        assert_eq!(route.via_router, SOURCE);
        assert_eq!(route.valid_until, now + ROUTE_INFO.route_lifetime);
        assert_eq!(route.preference, ROUTE_INFO.preference);
        assert!(route.is_valid(now));

        // A zero route lifetime expires only the RIO-learned route
        let mut expire = ROUTE_INFO;
        expire.route_lifetime = Duration::ZERO;
        slaac.process_advertisement(&SOURCE, VALID, None, expire.into(), now);
        assert!(
            !slaac
                .routes()
                .iter()
                .find(|r| r.cidr == cidr)
                .unwrap()
                .is_valid(now)
        );
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

        slaac.process_advertisement(&SOURCE, Duration::ZERO, None, route_info, now);

        assert_eq!(slaac.routes().len(), 2);
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

        slaac.process_advertisement(&SOURCE, VALID, None, route_info.into(), now);

        let route = slaac.routes().first().unwrap();
        assert_eq!(route.cidr, IPV6_DEFAULT);
        assert_eq!(route.valid_until, now + route_info.route_lifetime);
        assert_eq!(route.preference, NdiscRoutePreference::High);

        let mut withdrawn = route_info;
        withdrawn.route_lifetime = Duration::ZERO;
        slaac.process_advertisement(&SOURCE, VALID, None, withdrawn.into(), now);
        assert!(!slaac.routes().first().unwrap().is_valid(now));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_route_preference_selects_best_router() {
        let now = Instant::from_millis(1);
        let mut slaac = Slaac::new();
        let mut low = ROUTE_INFO;
        low.preference = NdiscRoutePreference::Low;

        slaac.process_advertisement(&SOURCE, Duration::ZERO, None, ROUTE_INFO.into(), now);
        slaac.process_advertisement(&SOURCE_2, Duration::ZERO, None, low.into(), now);

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
    fn test_ra_route_info_reserved_preference() {
        let mut slaac = Slaac::new();
        let now = Instant::from_millis(1);

        // Options with the reserved preference must be ignored (RFC 4191)
        let mut reserved = ROUTE_INFO;
        reserved.preference = crate::wire::NdiscRoutePreference::Unknown(2);
        slaac.process_advertisement(&SOURCE, Duration::ZERO, None, reserved.into(), now);
        assert!(slaac.routes().is_empty());
        assert!(!slaac.sync_required(now));
    }
}
