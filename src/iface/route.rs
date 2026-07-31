use heapless::Vec;

use crate::config::IFACE_MAX_ROUTE_COUNT;
use crate::time::Instant;
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::NdiscRoutePreference;
use crate::wire::{IpAddress, IpCidr};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteTableFull;

impl core::fmt::Display for RouteTableFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Route table full")
    }
}

impl core::error::Error for RouteTableFull {}

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddress,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

/// RFC 4191 metadata associated with one SLAAC-owned public route.
#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LearnedRoute {
    pub(crate) cidr: Ipv6Cidr,
    pub(crate) via_router: Ipv6Address,
    pub(crate) valid_until: Option<Instant>,
    pub(crate) preference: NdiscRoutePreference,
    pub(crate) order: u32,
}

#[cfg(feature = "proto-ipv6-rio")]
impl LearnedRoute {
    fn as_interface_route(&self) -> Route {
        Route {
            cidr: self.cidr.into(),
            via_router: self.via_router.into(),
            preferred_until: None,
            expires_at: self.valid_until,
        }
    }
}

#[cfg(feature = "proto-ipv6-rio")]
const NO_ROUTE_SLOT: u32 = u32::MAX;
#[cfg(feature = "proto-ipv6-rio")]
const AMBIGUOUS_ROUTE_SLOT: u32 = u32::MAX - 1;

#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteOwnership {
    Configured,
    Learned {
        valid_until: Option<Instant>,
        preference: NdiscRoutePreference,
        order: u32,
        selected: bool,
    },
}

/// Ownership and lookup index for one public IPv6 route slot.
///
/// The public route table remains the source of truth. This sidecar records
/// which *unique slot* is managed by SLAAC, so equal application routes can
/// never be mistaken for learned routes merely because their values match.
#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedRoute {
    cidr: Ipv6Cidr,
    via_router: Ipv6Address,
    slot: u32,
    ownership: RouteOwnership,
}

#[cfg(feature = "proto-ipv6-rio")]
impl IndexedRoute {
    fn configured(cidr: Ipv6Cidr, via_router: Ipv6Address, slot: usize) -> Self {
        Self {
            cidr,
            via_router,
            slot: u32::try_from(slot).expect("route-table slot fits in u32"),
            ownership: RouteOwnership::Configured,
        }
    }

    fn learned(route: LearnedRoute, slot: usize) -> Self {
        Self {
            cidr: route.cidr,
            via_router: route.via_router,
            slot: u32::try_from(slot).expect("route-table slot fits in u32"),
            ownership: RouteOwnership::Learned {
                valid_until: route.valid_until,
                preference: route.preference,
                order: route.order,
                selected: false,
            },
        }
    }

    fn identity_cmp(&self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) -> core::cmp::Ordering {
        (self.cidr, self.via_router).cmp(&(*cidr, *via_router))
    }

    fn sort_cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.cidr, self.via_router, self.slot).cmp(&(other.cidr, other.via_router, other.slot))
    }

    fn matches_public_route(&self, route: &Route) -> bool {
        let RouteOwnership::Learned { valid_until, .. } = self.ownership else {
            return false;
        };
        route.cidr == self.cidr.into()
            && route.via_router == self.via_router.into()
            && route.preferred_until.is_none()
            && route.expires_at == valid_until
    }

    fn as_learned(&self) -> Option<LearnedRoute> {
        let RouteOwnership::Learned {
            valid_until,
            preference,
            order,
            ..
        } = self.ownership
        else {
            return None;
        };
        Some(LearnedRoute {
            cidr: self.cidr,
            via_router: self.via_router,
            valid_until,
            preference,
            order,
        })
    }
}

#[cfg(feature = "proto-ipv4")]
const IPV4_DEFAULT: IpCidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0));
#[cfg(feature = "proto-ipv6")]
const IPV6_DEFAULT: IpCidr =
    IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns `true` if the route is a default route for IPv6.
    #[cfg(feature = "proto-ipv6")]
    pub fn is_ipv6_gateway(&self) -> bool {
        self.cidr == IPV6_DEFAULT
    }

    /// Returns `true` if the route is a default route for IPv4.
    #[cfg(feature = "proto-ipv4")]
    pub fn is_ipv4_gateway(&self) -> bool {
        self.cidr == IPV4_DEFAULT
    }
}

/// A routing table.
#[derive(Debug)]
pub struct Routes {
    storage: Vec<Route, IFACE_MAX_ROUTE_COUNT>,
    #[cfg(feature = "proto-ipv6-rio")]
    index: Vec<IndexedRoute, IFACE_MAX_ROUTE_COUNT>,
}

impl Routes {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
            #[cfg(feature = "proto-ipv6-rio")]
            index: Vec::new(),
        }
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut Vec<Route, IFACE_MAX_ROUTE_COUNT>)>(&mut self, f: F) {
        f(&mut self.storage);
        #[cfg(feature = "proto-ipv6-rio")]
        if !self.index.is_empty() || self.storage.iter().any(|route| Self::ipv6_identity(route).is_some())
        {
            // Callers edit the raw public vector through this API. Rebuild
            // slot ownership after the opaque edit so duplicate application
            // routes cannot inherit learned metadata by value.
            //
            // A table that holds no IPv6 routes has no ownership to track, so
            // an IPv4-only application does not pay for the rebuild.
            self.rebuild_route_index();
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn ipv6_identity(route: &Route) -> Option<(Ipv6Cidr, Ipv6Address)> {
        match (route.cidr, route.via_router) {
            (IpCidr::Ipv6(cidr), IpAddress::Ipv6(via_router)) => Some((cidr, via_router)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn identity_range(
        index: &[IndexedRoute],
        cidr: &Ipv6Cidr,
        via_router: &Ipv6Address,
    ) -> core::ops::Range<usize> {
        let start = index.partition_point(|entry| {
            entry.identity_cmp(cidr, via_router) == core::cmp::Ordering::Less
        });
        let end = index.partition_point(|entry| {
            entry.identity_cmp(cidr, via_router) != core::cmp::Ordering::Greater
        });
        start..end
    }

    #[cfg(feature = "proto-ipv6-rio")]
    fn rebuild_route_index(&mut self) {
        // Only a uniquely matching public slot may retain learned
        // ownership. Two equal values are intentionally both configured,
        // because an opaque application edit gives us no safe way to tell
        // which occurrence the application owns.
        self.index
            .retain(|entry| matches!(entry.ownership, RouteOwnership::Learned { .. }));
        for entry in &mut self.index {
            entry.slot = NO_ROUTE_SLOT;
        }

        for (slot, route) in self.storage.iter().enumerate() {
            let Some((cidr, via_router)) = Self::ipv6_identity(route) else {
                continue;
            };
            let range = Self::identity_range(&self.index, &cidr, &via_router);
            if range.is_empty() {
                continue;
            }
            let Some(entry) = self.index.get_mut(range.start) else {
                continue;
            };
            debug_assert_eq!(range.len(), 1);
            entry.slot = match entry.slot {
                NO_ROUTE_SLOT if entry.matches_public_route(route) => {
                    u32::try_from(slot).expect("route-table slot fits in u32")
                }
                _ => AMBIGUOUS_ROUTE_SLOT,
            };
        }

        self.index.retain(|entry| entry.slot < AMBIGUOUS_ROUTE_SLOT);
        let learned_count = self.index.len();

        for (slot, route) in self.storage.iter().enumerate() {
            let Some((cidr, via_router)) = Self::ipv6_identity(route) else {
                continue;
            };
            let range = Self::identity_range(&self.index[..learned_count], &cidr, &via_router);
            let is_learned_slot = !range.is_empty()
                && self.index.get(range.start).is_some_and(|entry| {
                    entry.slot == u32::try_from(slot).expect("route-table slot fits in u32")
                });
            if !is_learned_slot {
                self.index
                    .push(IndexedRoute::configured(cidr, via_router, slot))
                    .expect("the IPv6 route index cannot exceed public route capacity");
            }
        }
        self.index.sort_unstable_by(IndexedRoute::sort_cmp);
    }

    /// Iterate over public routes.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn iter(&self) -> core::slice::Iter<'_, Route> {
        self.storage.iter()
    }

    /// Return learned-route metadata for an exact public route.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn learned(&self, route: &Route) -> Option<LearnedRoute> {
        let (cidr, via_router) = Self::ipv6_identity(route)?;
        let range = Self::identity_range(&self.index, &cidr, &via_router);
        if range.len() != 1 {
            return None;
        }
        let entry = self.index.get(range.start)?;
        entry
            .matches_public_route(route)
            .then(|| entry.as_learned())
            .flatten()
    }

    /// Reconcile the public table with retained learned-route candidates.
    ///
    /// Candidates must have unique `(prefix, router)` identities and be
    /// ordered from most to least useful. The callback may be invoked twice
    /// for each index.
    ///
    /// The indexed callback avoids returning a capacity-sized collection on
    /// the synchronization stack. Maintenance may rescan the bounded source,
    /// while packet forwarding remains a single public-table pass.
    #[cfg(feature = "proto-ipv6-rio")]
    pub(crate) fn reconcile_learned<F>(&mut self, candidate_count: usize, mut candidate_at: F)
    where
        F: FnMut(usize) -> Option<LearnedRoute>,
    {
        for entry in &mut self.index {
            if let RouteOwnership::Learned { selected, .. } = &mut entry.ownership {
                *selected = false;
            }
        }

        let learned_count = self
            .index
            .iter()
            .filter(|entry| matches!(entry.ownership, RouteOwnership::Learned { .. }))
            .count();
        let configured_count = self.storage.len() - learned_count;
        let target_count = IFACE_MAX_ROUTE_COUNT - configured_count;
        let mut selected_count = 0;

        // Candidates arrive in descending usefulness order. Marking the
        // first non-conflicting identities lets the second pass materialize
        // exactly the bounded target set without a capacity-sized stack copy.
        for candidate_index in 0..candidate_count {
            if selected_count == target_count {
                break;
            }
            let Some(candidate) = candidate_at(candidate_index) else {
                continue;
            };
            let range = Self::identity_range(&self.index, &candidate.cidr, &candidate.via_router);
            if self.index[range.clone()]
                .iter()
                .any(|entry| matches!(entry.ownership, RouteOwnership::Configured))
            {
                continue;
            }
            if let Some(entry) = self.index[range]
                .iter_mut()
                .find(|entry| matches!(entry.ownership, RouteOwnership::Learned { .. }))
            {
                let RouteOwnership::Learned { selected, .. } = &mut entry.ownership else {
                    unreachable!()
                };
                if *selected {
                    continue;
                }
                *selected = true;
            }
            selected_count += 1;
            if selected_count == target_count {
                break;
            }
        }

        // The identity index may contain C equal configured routes.
        // Walking such an identity range once per public slot would become
        // quadratic, so temporarily order the sidecar by its unique slot and
        // merge it with the public vector in one linear pass.
        self.index.sort_unstable_by_key(|entry| entry.slot);
        let (storage, index) = (&mut self.storage, &mut self.index);
        let mut old_slot = 0usize;
        let mut new_slot = 0usize;
        let mut indexed_slot = 0usize;
        storage.retain(|route| {
            let current_slot = old_slot;
            old_slot += 1;
            let keep = if let Some((cidr, via_router)) = Self::ipv6_identity(route) {
                let entry = index
                    .get_mut(indexed_slot)
                    .expect("every public IPv6 route has an index entry");
                indexed_slot += 1;
                debug_assert_eq!(entry.slot as usize, current_slot);
                debug_assert_eq!((entry.cidr, entry.via_router), (cidr, via_router));
                if matches!(
                    entry.ownership,
                    RouteOwnership::Learned {
                        selected: false,
                        ..
                    }
                ) {
                    false
                } else {
                    entry.slot = u32::try_from(new_slot).expect("route-table slot fits in u32");
                    true
                }
            } else {
                true
            };
            if keep {
                new_slot += 1;
            }
            keep
        });
        debug_assert_eq!(indexed_slot, index.len());
        index.retain(|entry| {
            !matches!(
                entry.ownership,
                RouteOwnership::Learned {
                    selected: false,
                    ..
                }
            )
        });
        self.index.sort_unstable_by(IndexedRoute::sort_cmp);

        let sorted_count = self.index.len();
        selected_count = 0;
        for candidate_index in 0..candidate_count {
            if selected_count == target_count {
                break;
            }
            let Some(candidate) = candidate_at(candidate_index) else {
                continue;
            };
            let range = Self::identity_range(
                &self.index[..sorted_count],
                &candidate.cidr,
                &candidate.via_router,
            );
            if self.index[range.clone()]
                .iter()
                .any(|entry| matches!(entry.ownership, RouteOwnership::Configured))
            {
                continue;
            }

            if let Some(entry) = self.index[range].iter_mut().find(|entry| {
                matches!(
                    entry.ownership,
                    RouteOwnership::Learned { selected: true, .. }
                )
            }) {
                let slot = entry.slot as usize;
                self.storage[slot].expires_at = candidate.valid_until;
                entry.ownership = RouteOwnership::Learned {
                    valid_until: candidate.valid_until,
                    preference: candidate.preference,
                    order: candidate.order,
                    selected: false,
                };
            } else {
                let slot = self.storage.len();
                self.storage
                    .push(candidate.as_interface_route())
                    .expect("candidate selection reserved a public route slot");
                self.index
                    .push(IndexedRoute::learned(candidate, slot))
                    .expect("the IPv6 route index cannot exceed public route capacity");
            }

            selected_count += 1;
            if selected_count == target_count {
                break;
            }
        }

        for entry in &mut self.index {
            if let RouteOwnership::Learned { selected, .. } = &mut entry.ownership {
                *selected = false;
            }
        }
        self.index.sort_unstable_by(IndexedRoute::sort_cmp);
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn add_default_ipv4_route(
        &mut self,
        gateway: Ipv4Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv4_route();
        self.storage
            .push(Route::new_ipv4_gateway(gateway))
            .map_err(|_| RouteTableFull)?;
        #[cfg(feature = "proto-ipv6-rio")]
        self.rebuild_route_index();
        Ok(old)
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn add_default_ipv6_route(
        &mut self,
        gateway: Ipv6Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv6_route();
        self.storage
            .push(Route::new_ipv6_gateway(gateway))
            .map_err(|_| RouteTableFull)?;
        #[cfg(feature = "proto-ipv6-rio")]
        self.rebuild_route_index();
        Ok(old)
    }

    /// Returns the ipv4 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_default_ipv4_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv4_gateway()).copied()
    }

    /// Returns the ipv6 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_default_ipv6_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv6_gateway()).copied()
    }

    /// Remove the default ipv4 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        let removed = if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_ipv4_gateway())
        {
            Some(self.storage.remove(i))
        } else {
            None
        };
        #[cfg(feature = "proto-ipv6-rio")]
        if removed.is_some() {
            self.rebuild_route_index();
        }
        removed
    }

    /// Remove the default ipv6 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        let removed = if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_ipv6_gateway())
        {
            Some(self.storage.remove(i))
        } else {
            None
        };
        #[cfg(feature = "proto-ipv6-rio")]
        if removed.is_some() {
            self.rebuild_route_index();
        }
        removed
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        assert!(addr.is_unicast());

        // Keep the ordinary lookup on its original path because only RIO
        // needs ownership filtering. Sending feature-off traffic through the
        // generic helper would add a predicate layer and copy a full Route.
        self.storage
            .iter()
            // Keep only matching routes
            .filter(|route| {
                if let Some(expires_at) = route.expires_at
                    && timestamp > expires_at
                {
                    return false;
                }
                route.cidr.contains_addr(addr)
            })
            // pick the most specific one (highest prefix_len)
            .max_by_key(|route| route.cidr.prefix_len())
            .map(|route| route.via_router)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv6")]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 1);
        pub const ADDR_1B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 13);
        pub const ADDR_1C: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 42);
        pub fn cidr_1() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), 64)
        }

        pub const ADDR_2A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 1);
        pub const ADDR_2B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 21);
        pub fn cidr_2() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 0), 64)
        }
    }

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
        pub const ADDR_1B: Ipv4Address = Ipv4Address::new(192, 0, 2, 13);
        pub const ADDR_1C: Ipv4Address = Ipv4Address::new(192, 0, 2, 42);
        pub fn cidr_1() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(192, 0, 2, 0), 24)
        }

        pub const ADDR_2A: Ipv4Address = Ipv4Address::new(198, 51, 100, 1);
        pub const ADDR_2B: Ipv4Address = Ipv4Address::new(198, 51, 100, 21);
        pub fn cidr_2() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(198, 51, 100, 0), 24)
        }
    }

    use self::mock::*;

    #[test]
    fn test_fill() {
        let mut routes = Routes::new();

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route = Route {
            cidr: cidr_1().into(),
            via_router: ADDR_1A.into(),
            preferred_until: None,
            expires_at: None,
        };
        routes.update(|storage| {
            storage.push(route).unwrap();
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route2 = Route {
            cidr: cidr_2().into(),
            via_router: ADDR_2A.into(),
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.update(|storage| {
            storage.push(route2).unwrap();
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn exact_application_duplicate_drops_learned_ownership() {
        let learned = LearnedRoute {
            cidr: cidr_1(),
            via_router: ADDR_2A,
            valid_until: Some(Instant::from_millis(100)),
            preference: NdiscRoutePreference::High,
            order: 7,
        };
        let mut routes = Routes::new();
        routes.reconcile_learned(1, |index| (index == 0).then_some(learned));
        assert_eq!(routes.storage.len(), 1);
        assert_eq!(routes.learned(&routes.storage[0]), Some(learned));

        let duplicate = learned.as_interface_route();
        routes.update(|storage| storage.push(duplicate).unwrap());

        // Equal route values do not reveal which slot the application
        // owns. Treating both as configured is the only choice that cannot
        // later remove the application's route as stale learned state.
        assert!(
            routes
                .storage
                .iter()
                .all(|route| routes.learned(route).is_none())
        );

        routes.update(|storage| {
            storage.remove(0);
        });
        routes.reconcile_learned(1, |index| (index == 0).then_some(learned));

        assert_eq!(routes.storage.len(), 1);
        assert_eq!(routes.storage[0].cidr, duplicate.cidr);
        assert_eq!(routes.storage[0].via_router, duplicate.via_router);
        assert!(routes.learned(&routes.storage[0]).is_none());
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn unrelated_application_update_preserves_unique_learned_slot() {
        let learned = LearnedRoute {
            cidr: cidr_1(),
            via_router: ADDR_2A,
            valid_until: Some(Instant::from_millis(100)),
            preference: NdiscRoutePreference::Medium,
            order: 3,
        };
        let configured = Route::new_ipv6_gateway(ADDR_1A);
        let mut routes = Routes::new();
        routes.reconcile_learned(1, |index| (index == 0).then_some(learned));

        routes.update(|storage| storage.push(configured).unwrap());

        assert_eq!(routes.storage.len(), 2);
        assert_eq!(routes.learned(&routes.storage[0]), Some(learned));
        assert!(routes.learned(&routes.storage[1]).is_none());
    }

    #[cfg(feature = "proto-ipv6-rio")]
    #[test]
    fn full_duplicate_identity_table_remains_configured() {
        let learned = LearnedRoute {
            cidr: cidr_1(),
            via_router: ADDR_2A,
            valid_until: Some(Instant::from_millis(100)),
            preference: NdiscRoutePreference::High,
            order: 1,
        };
        let configured = learned.as_interface_route();
        let mut routes = Routes::new();
        routes.update(|storage| {
            for _ in 0..IFACE_MAX_ROUTE_COUNT {
                storage.push(configured).unwrap();
            }
        });

        routes.reconcile_learned(1, |index| (index == 0).then_some(learned));

        assert_eq!(routes.storage.len(), IFACE_MAX_ROUTE_COUNT);
        assert!(
            routes
                .storage
                .iter()
                .all(|route| routes.learned(route).is_none())
        );
    }
}
