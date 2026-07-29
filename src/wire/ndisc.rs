use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};
#[cfg(feature = "proto-ipv6-rio")]
use crate::config::IFACE_MAX_ROUTE_COUNT;
use crate::time::Duration;
use crate::wire::Ipv6Address;
use crate::wire::RawHardwareAddress;
use crate::wire::icmpv6::{Message, Packet, field};
use crate::wire::{NdiscOption, NdiscOptionRepr};
use crate::wire::{NdiscPrefixInformation, NdiscRedirectedHeader};
#[cfg(feature = "proto-ipv6-rio")]
use crate::wire::{NdiscRouteInformation, NdiscRoutePreference};

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct RouterFlags: u8 {
        const MANAGED = 0b10000000;
        const OTHER   = 0b01000000;
    }
}

#[cfg(feature = "proto-ipv6-rio")]
const ROUTER_PREFERENCE_MASK: u8 = 0b0001_1000;

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct NeighborFlags: u8 {
        const ROUTER    = 0b10000000;
        const SOLICITED = 0b01000000;
        const OVERRIDE  = 0b00100000;
    }
}

/// Getters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the current hop limit field.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CUR_HOP_LIMIT]
    }

    /// Return the Router Advertisement flags.
    #[inline]
    pub fn router_flags(&self) -> RouterFlags {
        let data = self.buffer.as_ref();
        RouterFlags::from_bits_truncate(data[field::ROUTER_FLAGS])
    }

    /// Return the default-router preference.
    #[cfg(feature = "proto-ipv6-rio")]
    #[inline]
    pub fn router_preference(&self) -> NdiscRoutePreference {
        let data = self.buffer.as_ref();
        NdiscRoutePreference::from((data[field::ROUTER_FLAGS] & ROUTER_PREFERENCE_MASK) >> 3)
    }

    /// Return the router lifetime field.
    #[inline]
    pub fn router_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_secs(NetworkEndian::read_u16(&data[field::ROUTER_LT]) as u64)
    }

    /// Return the reachable time field.
    #[inline]
    pub fn reachable_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::REACHABLE_TM]) as u64)
    }

    /// Return the retransmit time field.
    #[inline]
    pub fn retrans_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::RETRANS_TM]) as u64)
    }
}

/// Common getters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the target address field.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_octets(data[field::TARGET_ADDR].try_into().unwrap())
    }
}

/// Getters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Neighbor Solicitation flags.
    #[inline]
    pub fn neighbor_flags(&self) -> NeighborFlags {
        let data = self.buffer.as_ref();
        NeighborFlags::from_bits_truncate(data[field::NEIGH_FLAGS])
    }
}

/// Getters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the destination address field.
    #[inline]
    pub fn dest_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_octets(data[field::DEST_ADDR].try_into().unwrap())
    }
}

/// Setters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the current hop limit field.
    #[inline]
    pub fn set_current_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CUR_HOP_LIMIT] = value;
    }

    /// Set the Router Advertisement flags.
    #[inline]
    pub fn set_router_flags(&mut self, flags: RouterFlags) {
        let data = self.buffer.as_mut();
        #[cfg(feature = "proto-ipv6-rio")]
        {
            // Preference shares this octet with the RFC 4861 flags, so a
            // caller updating only those flags must not erase an earlier Prf.
            data[field::ROUTER_FLAGS] =
                flags.bits() | (data[field::ROUTER_FLAGS] & ROUTER_PREFERENCE_MASK);
        }
        #[cfg(not(feature = "proto-ipv6-rio"))]
        {
            data[field::ROUTER_FLAGS] = flags.bits();
        }
    }

    /// Set the default-router preference while preserving the other flags.
    #[cfg(feature = "proto-ipv6-rio")]
    #[inline]
    pub fn set_router_preference(&mut self, preference: NdiscRoutePreference) {
        let data = self.buffer.as_mut();
        data[field::ROUTER_FLAGS] = (data[field::ROUTER_FLAGS] & !ROUTER_PREFERENCE_MASK)
            | ((u8::from(preference.normalized_for_router_header()) << 3) & ROUTER_PREFERENCE_MASK);
    }

    /// Set the router lifetime field.
    #[inline]
    pub fn set_router_lifetime(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ROUTER_LT], value.secs() as u16);
    }

    /// Set the reachable time field.
    #[inline]
    pub fn set_reachable_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::REACHABLE_TM], value.total_millis() as u32);
    }

    /// Set the retransmit time field.
    #[inline]
    pub fn set_retrans_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RETRANS_TM], value.total_millis() as u32);
    }
}

/// Common setters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the target address field.
    #[inline]
    pub fn set_target_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::TARGET_ADDR].copy_from_slice(&value.octets());
    }
}

/// Setters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Neighbor Solicitation flags.
    #[inline]
    pub fn set_neighbor_flags(&mut self, flags: NeighborFlags) {
        self.buffer.as_mut()[field::NEIGH_FLAGS] = flags.bits();
    }
}

/// Setters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the destination address field.
    #[inline]
    pub fn set_dest_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::DEST_ADDR].copy_from_slice(&value.octets());
    }
}

/// Route Information options carried by a Router Advertisement.
#[cfg(feature = "proto-ipv6-rio")]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteInformationList {
    entries: [Option<NdiscRouteInformation>; IFACE_MAX_ROUTE_COUNT],
}

#[cfg(feature = "proto-ipv6-rio")]
impl RouteInformationList {
    /// Create an empty list.
    pub const fn new() -> Self {
        Self {
            entries: [None; IFACE_MAX_ROUTE_COUNT],
        }
    }

    /// Append an option to the list.
    ///
    /// A withdrawal or a higher-preference duplicate replaces the existing
    /// entry, so emission never includes a duplicate prefix and prefix length.
    /// Returns the option unchanged if it is invalid or cannot be retained
    /// within the configured route capacity.
    pub fn push(
        &mut self,
        route_info: NdiscRouteInformation,
    ) -> core::result::Result<(), NdiscRouteInformation> {
        if !route_info.is_valid_route_info() {
            return Err(route_info);
        }

        let duplicate = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.same_prefix(&route_info)));
        if let Some(index) = duplicate {
            let existing = self.entries[index].unwrap();
            let is_withdrawal = route_info.route_lifetime == Duration::ZERO;
            let replaces_lower_preference = existing.route_lifetime != Duration::ZERO
                && route_info.preference.rank() > existing.preference.rank();

            // Emission canonicalizes reserved host bits, so replace the
            // canonical duplicate in place rather than emitting both inputs.
            if is_withdrawal || replaces_lower_preference {
                self.entries[index] = Some(route_info);
                return Ok(());
            }
            return Err(route_info);
        }

        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.is_none()) {
            *entry = Some(route_info);
            Ok(())
        } else if route_info.route_lifetime == Duration::ZERO {
            // A lost withdrawal can preserve a stale route indefinitely. When
            // bounded storage is full, retain it ahead of the first update.
            if let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| entry.is_some_and(|entry| entry.route_lifetime != Duration::ZERO))
            {
                *entry = Some(route_info);
                Ok(())
            } else {
                Err(route_info)
            }
        } else {
            Err(route_info)
        }
    }

    /// Iterate over the options in advertisement order.
    pub fn iter(&self) -> impl Iterator<Item = NdiscRouteInformation> + '_ {
        self.entries.iter().flatten().copied()
    }

    const fn buffer_len(&self) -> usize {
        let mut len = 0;
        let mut index = 0;
        while index < IFACE_MAX_ROUTE_COUNT {
            if let Some(route_info) = self.entries[index] {
                len += NdiscOptionRepr::RouteInformation(route_info).buffer_len();
            }
            index += 1;
        }
        len
    }
}

#[cfg(feature = "proto-ipv6-rio")]
impl Default for RouteInformationList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "proto-ipv6-rio")]
impl From<NdiscRouteInformation> for RouteInformationList {
    fn from(route_info: NdiscRouteInformation) -> Self {
        let mut list = Self::new();
        list.push(route_info)
            .expect("invalid Route Information option");
        list
    }
}

/// A high-level representation of an Neighbor Discovery packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'a> {
    RouterSolicit {
        lladdr: Option<RawHardwareAddress>,
    },
    RouterAdvert {
        hop_limit: u8,
        flags: RouterFlags,
        #[cfg(feature = "proto-ipv6-rio")]
        preference: NdiscRoutePreference,
        router_lifetime: Duration,
        reachable_time: Duration,
        retrans_time: Duration,
        lladdr: Option<RawHardwareAddress>,
        mtu: Option<u32>,
        prefix_info: Option<NdiscPrefixInformation>,
        #[cfg(feature = "proto-ipv6-rio")]
        route_info: RouteInformationList,
    },
    NeighborSolicit {
        target_addr: Ipv6Address,
        lladdr: Option<RawHardwareAddress>,
    },
    NeighborAdvert {
        flags: NeighborFlags,
        target_addr: Ipv6Address,
        lladdr: Option<RawHardwareAddress>,
    },
    Redirect {
        target_addr: Ipv6Address,
        dest_addr: Ipv6Address,
        lladdr: Option<RawHardwareAddress>,
        redirected_hdr: Option<NdiscRedirectedHeader<'a>>,
    },
}

impl<'a> Repr<'a> {
    /// Parse an NDISC packet and return a high-level representation of the
    /// packet.
    #[allow(clippy::single_match)]
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        let (mut src_ll_addr, mut mtu, mut prefix_info, mut target_ll_addr, mut redirected_hdr) =
            (None, None, None, None, None);
        #[cfg(feature = "proto-ipv6-rio")]
        let mut route_info = RouteInformationList::new();

        let mut offset = 0;
        while packet.payload().len() > offset {
            let pkt = NdiscOption::new_checked(&packet.payload()[offset..])?;

            // If an option doesn't parse, ignore it and still parse the others.
            if let Ok(opt) = NdiscOptionRepr::parse(&pkt) {
                match opt {
                    NdiscOptionRepr::SourceLinkLayerAddr(addr) => src_ll_addr = Some(addr),
                    NdiscOptionRepr::TargetLinkLayerAddr(addr) => target_ll_addr = Some(addr),
                    NdiscOptionRepr::PrefixInformation(prefix) => prefix_info = Some(prefix),
                    NdiscOptionRepr::RedirectedHeader(redirect) => redirected_hdr = Some(redirect),
                    NdiscOptionRepr::Mtu(m) => mtu = Some(m),
                    #[cfg(feature = "proto-ipv6-rio")]
                    NdiscOptionRepr::RouteInformation(info) if info.is_valid_route_info() => {
                        let _ = route_info.push(info);
                    }
                    _ => {}
                }
            }

            let len = pkt.data_len() as usize * 8;
            if len == 0 {
                return Err(Error);
            }
            offset += len;
        }

        match packet.msg_type() {
            Message::RouterSolicit => Ok(Repr::RouterSolicit {
                lladdr: src_ll_addr,
            }),
            Message::RouterAdvert => Ok(Repr::RouterAdvert {
                hop_limit: packet.current_hop_limit(),
                flags: packet.router_flags(),
                #[cfg(feature = "proto-ipv6-rio")]
                preference: {
                    // A zero lifetime makes Prf meaningless, and reserved 10
                    // is explicitly received as the default Medium value.
                    if packet.router_lifetime() == Duration::ZERO {
                        NdiscRoutePreference::Medium
                    } else {
                        packet.router_preference().normalized_for_router_header()
                    }
                },
                router_lifetime: packet.router_lifetime(),
                reachable_time: packet.reachable_time(),
                retrans_time: packet.retrans_time(),
                lladdr: src_ll_addr,
                mtu,
                prefix_info,
                #[cfg(feature = "proto-ipv6-rio")]
                route_info,
            }),
            Message::NeighborSolicit => Ok(Repr::NeighborSolicit {
                target_addr: packet.target_addr(),
                lladdr: src_ll_addr,
            }),
            Message::NeighborAdvert => Ok(Repr::NeighborAdvert {
                flags: packet.neighbor_flags(),
                target_addr: packet.target_addr(),
                lladdr: target_ll_addr,
            }),
            Message::Redirect => Ok(Repr::Redirect {
                target_addr: packet.target_addr(),
                dest_addr: packet.dest_addr(),
                lladdr: src_ll_addr,
                redirected_hdr,
            }),
            _ => Err(Error),
        }
    }

    pub const fn buffer_len(&self) -> usize {
        match self {
            &Repr::RouterSolicit { lladdr } => match lladdr {
                Some(addr) => {
                    field::UNUSED.end + { NdiscOptionRepr::SourceLinkLayerAddr(addr).buffer_len() }
                }
                None => field::UNUSED.end,
            },
            &Repr::RouterAdvert {
                lladdr,
                mtu,
                prefix_info,
                #[cfg(feature = "proto-ipv6-rio")]
                route_info,
                ..
            } => {
                let mut offset = 0;
                if let Some(lladdr) = lladdr {
                    offset += NdiscOptionRepr::TargetLinkLayerAddr(lladdr).buffer_len();
                }
                if let Some(mtu) = mtu {
                    offset += NdiscOptionRepr::Mtu(mtu).buffer_len();
                }
                if let Some(prefix_info) = prefix_info {
                    offset += NdiscOptionRepr::PrefixInformation(prefix_info).buffer_len();
                }
                #[cfg(feature = "proto-ipv6-rio")]
                {
                    offset += route_info.buffer_len();
                }
                field::RETRANS_TM.end + offset
            }
            &Repr::NeighborSolicit { lladdr, .. } | &Repr::NeighborAdvert { lladdr, .. } => {
                let mut offset = field::TARGET_ADDR.end;
                if let Some(lladdr) = lladdr {
                    offset += NdiscOptionRepr::SourceLinkLayerAddr(lladdr).buffer_len();
                }
                offset
            }
            &Repr::Redirect {
                lladdr,
                redirected_hdr,
                ..
            } => {
                let mut offset = field::DEST_ADDR.end;
                if let Some(lladdr) = lladdr {
                    offset += NdiscOptionRepr::TargetLinkLayerAddr(lladdr).buffer_len();
                }
                if let Some(NdiscRedirectedHeader { header, data }) = redirected_hdr {
                    offset +=
                        NdiscOptionRepr::RedirectedHeader(NdiscRedirectedHeader { header, data })
                            .buffer_len();
                }
                offset
            }
        }
    }

    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        match *self {
            Repr::RouterSolicit { lladdr } => {
                packet.set_msg_type(Message::RouterSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::RouterAdvert {
                hop_limit,
                flags,
                #[cfg(feature = "proto-ipv6-rio")]
                preference,
                router_lifetime,
                reachable_time,
                retrans_time,
                lladdr,
                mtu,
                prefix_info,
                #[cfg(feature = "proto-ipv6-rio")]
                route_info,
            } => {
                packet.set_msg_type(Message::RouterAdvert);
                packet.set_msg_code(0);
                packet.set_current_hop_limit(hop_limit);
                packet.set_router_flags(flags);
                #[cfg(feature = "proto-ipv6-rio")]
                {
                    // RFC 4191 requires Medium on the wire when the router
                    // lifetime is zero, regardless of the representation.
                    let preference = if router_lifetime == Duration::ZERO {
                        NdiscRoutePreference::Medium
                    } else {
                        preference.normalized_for_router_header()
                    };
                    packet.set_router_preference(preference);
                }
                packet.set_router_lifetime(router_lifetime);
                packet.set_reachable_time(reachable_time);
                packet.set_retrans_time(retrans_time);
                let mut offset = 0;
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                    let opt = NdiscOptionRepr::SourceLinkLayerAddr(lladdr);
                    opt.emit(&mut opt_pkt);
                    offset += opt.buffer_len();
                }
                if let Some(mtu) = mtu {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::Mtu(mtu).emit(&mut opt_pkt);
                    offset += NdiscOptionRepr::Mtu(mtu).buffer_len();
                }
                if let Some(prefix_info) = prefix_info {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::PrefixInformation(prefix_info).emit(&mut opt_pkt);
                    #[cfg(feature = "proto-ipv6-rio")]
                    {
                        offset += NdiscOptionRepr::PrefixInformation(prefix_info).buffer_len();
                    }
                }
                #[cfg(feature = "proto-ipv6-rio")]
                for route_info in route_info.iter() {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    let opt = NdiscOptionRepr::RouteInformation(route_info);
                    opt.emit(&mut opt_pkt);
                    offset += opt.buffer_len();
                }
            }

            Repr::NeighborSolicit {
                target_addr,
                lladdr,
            } => {
                packet.set_msg_type(Message::NeighborSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::NeighborAdvert {
                flags,
                target_addr,
                lladdr,
            } => {
                packet.set_msg_type(Message::NeighborAdvert);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_neighbor_flags(flags);
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                    NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::Redirect {
                target_addr,
                dest_addr,
                lladdr,
                redirected_hdr,
            } => {
                packet.set_msg_type(Message::Redirect);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.set_dest_addr(dest_addr);
                let offset = match lladdr {
                    Some(lladdr) => {
                        let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_mut());
                        NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                        NdiscOptionRepr::TargetLinkLayerAddr(lladdr).buffer_len()
                    }
                    None => 0,
                };
                if let Some(redirected_hdr) = redirected_hdr {
                    let mut opt_pkt =
                        NdiscOption::new_unchecked(&mut packet.payload_mut()[offset..]);
                    NdiscOptionRepr::RedirectedHeader(redirected_hdr).emit(&mut opt_pkt);
                }
            }
        }
    }
}

#[cfg(feature = "medium-ethernet")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::phy::ChecksumCapabilities;
    use crate::wire::EthernetAddress;
    use crate::wire::Icmpv6Repr;

    const MOCK_IP_ADDR_1: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const MOCK_IP_ADDR_2: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    static ROUTER_ADVERT_BYTES: [u8; 24] = [
        0x86, 0x00, 0xa9, 0xde, 0x40, 0x80, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03,
        0x84, 0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    ];
    static SOURCE_LINK_LAYER_OPT: [u8; 8] = [0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn create_repr<'a>() -> Icmpv6Repr<'a> {
        Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            #[cfg(feature = "proto-ipv6-rio")]
            preference: NdiscRoutePreference::Medium,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::from_millis(900),
            retrans_time: Duration::from_millis(900),
            lladdr: Some(EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).into()),
            mtu: None,
            prefix_info: None,
            #[cfg(feature = "proto-ipv6-rio")]
            route_info: RouteInformationList::new(),
        })
    }

    #[test]
    fn test_router_advert_deconstruct() {
        let packet = Packet::new_unchecked(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::RouterAdvert);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.current_hop_limit(), 64);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        #[cfg(feature = "proto-ipv6-rio")]
        assert_eq!(packet.router_preference(), NdiscRoutePreference::Medium);
        assert_eq!(packet.router_lifetime(), Duration::from_secs(900));
        assert_eq!(packet.reachable_time(), Duration::from_millis(900));
        assert_eq!(packet.retrans_time(), Duration::from_millis(900));
        assert_eq!(packet.payload(), &SOURCE_LINK_LAYER_OPT[..]);
    }

    #[test]
    fn test_router_advert_construct() {
        let mut bytes = vec![0x0; 24];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        #[cfg(feature = "proto-ipv6-rio")]
        packet.set_router_preference(NdiscRoutePreference::Medium);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        packet
            .payload_mut()
            .copy_from_slice(&SOURCE_LINK_LAYER_OPT[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&*packet.into_inner(), &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_router_advert_preference() {
        let mut bytes = ROUTER_ADVERT_BYTES;
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_router_preference(NdiscRoutePreference::High);
        packet.set_router_flags(RouterFlags::MANAGED);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        assert_eq!(packet.router_preference(), NdiscRoutePreference::High);

        let packet = Packet::new_unchecked(&bytes[..]);
        assert!(matches!(
            Repr::parse(&packet),
            Ok(Repr::RouterAdvert {
                preference: NdiscRoutePreference::High,
                ..
            })
        ));

        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_router_preference(NdiscRoutePreference::Unknown(2));
        assert_eq!(packet.router_preference(), NdiscRoutePreference::Medium);

        bytes[5] = RouterFlags::MANAGED.bits() | (2 << 3);
        let packet = Packet::new_unchecked(&bytes[..]);
        assert!(matches!(
            Repr::parse(&packet),
            Ok(Repr::RouterAdvert {
                preference: NdiscRoutePreference::Medium,
                ..
            })
        ));

        bytes[5] = RouterFlags::MANAGED.bits() | (1 << 3);
        bytes[6..8].fill(0);
        let packet = Packet::new_unchecked(&bytes[..]);
        assert!(matches!(
            Repr::parse(&packet),
            Ok(Repr::RouterAdvert {
                preference: NdiscRoutePreference::Medium,
                ..
            })
        ));

        let repr = Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            preference: NdiscRoutePreference::High,
            router_lifetime: Duration::ZERO,
            reachable_time: Duration::ZERO,
            retrans_time: Duration::ZERO,
            lladdr: None,
            mtu: None,
            prefix_info: None,
            route_info: RouteInformationList::new(),
        };
        let mut bytes = [0; 16];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        repr.emit(&mut packet);
        assert_eq!(packet.router_preference(), NdiscRoutePreference::Medium);
    }

    #[test]
    fn test_router_advert_repr_parse() {
        let packet = Packet::new_unchecked(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(
            Icmpv6Repr::parse(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::default()
            )
            .unwrap(),
            create_repr()
        );
    }

    #[test]
    fn test_router_advert_repr_emit() {
        let mut bytes = [0x2a; 24];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        create_repr().emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    #[cfg(not(feature = "proto-ipv6-rio"))]
    fn test_router_advert_ignores_route_info_when_disabled() {
        let route_info = [
            0x18, 0x02, 0x40, 0x00, 0x00, 0x00, 0x07, 0x08, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        packet.payload_mut()[..8].copy_from_slice(&SOURCE_LINK_LAYER_OPT);
        packet.payload_mut()[8..].copy_from_slice(&route_info);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        let packet = Packet::new_unchecked(&bytes[..]);

        assert_eq!(
            Icmpv6Repr::parse(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::default()
            )
            .unwrap(),
            create_repr()
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_router_advert_ignores_malformed_route_info() {
        let mut bytes = [0; 64];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_preference(NdiscRoutePreference::High);
        packet.set_router_lifetime(Duration::from_secs(900));

        // Length 4 is not a valid RIO, but it is nonzero and fully present.
        // The valid option following it must still be processed.
        packet.payload_mut()[..8].copy_from_slice(&[0x18, 0x04, 0x40, 0, 0, 0, 0x07, 0x08]);
        packet.payload_mut()[32..48].copy_from_slice(&[
            0x18, 0x02, 0x40, 0x08, 0x00, 0x00, 0x07, 0x08, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let packet = Packet::new_unchecked(&bytes[..]);
        assert!(matches!(
            Repr::parse(&packet),
            Ok(Repr::RouterAdvert {
                preference: NdiscRoutePreference::High,
                route_info,
                ..
            }) if matches!(
                route_info.iter().next(),
                Some(NdiscRouteInformation {
                    prefix_len: 64,
                    preference: NdiscRoutePreference::High,
                    ..
                })
            )
        ));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_router_advert_multiple_route_info() {
        use crate::wire::{NdiscRouteInformation, NdiscRoutePreference};

        let first = NdiscRouteInformation {
            prefix_len: 64,
            preference: NdiscRoutePreference::High,
            route_lifetime: Duration::from_secs(1800),
            prefix: Ipv6Address::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
        };
        let second = NdiscRouteInformation {
            prefix_len: 120,
            preference: NdiscRoutePreference::Low,
            route_lifetime: Duration::from_secs(900),
            prefix: Ipv6Address::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0xff00),
        };
        let mut route_info = RouteInformationList::from(first);
        route_info.push(second).unwrap();
        let repr = Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::empty(),
            preference: NdiscRoutePreference::High,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::ZERO,
            retrans_time: Duration::ZERO,
            lladdr: None,
            mtu: None,
            prefix_info: None,
            route_info,
        });
        let mut bytes = vec![0; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        let packet = Packet::new_unchecked(&bytes[..]);

        assert_eq!(
            Icmpv6Repr::parse(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::default()
            ),
            Ok(repr)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_route_information_list_validation_and_replacement() {
        let base = NdiscRouteInformation {
            prefix_len: 53,
            preference: NdiscRoutePreference::Low,
            route_lifetime: Duration::from_secs(900),
            prefix: Ipv6Address::new(0x2001, 0xdb8, 1, 0xa800, 0, 0, 0, 1),
        };
        let mut list = RouteInformationList::from(base);

        let higher_duplicate = NdiscRouteInformation {
            preference: NdiscRoutePreference::High,
            prefix: Ipv6Address::new(0x2001, 0xdb8, 1, 0xafff, 0, 0, 0, 2),
            ..base
        };
        assert_eq!(list.push(higher_duplicate), Ok(()));
        assert_eq!(list.iter().count(), 1);
        assert_eq!(list.iter().next(), Some(higher_duplicate));

        let lower_duplicate = NdiscRouteInformation {
            preference: NdiscRoutePreference::Medium,
            ..base
        };
        assert_eq!(list.push(lower_duplicate), Err(lower_duplicate));

        let withdrawal = NdiscRouteInformation {
            route_lifetime: Duration::ZERO,
            ..base
        };
        assert_eq!(list.push(withdrawal), Ok(()));
        assert_eq!(list.iter().next(), Some(withdrawal));

        let invalid_prefix = NdiscRouteInformation {
            prefix_len: 129,
            ..base
        };
        assert_eq!(list.push(invalid_prefix), Err(invalid_prefix));
        let invalid_preference = NdiscRouteInformation {
            preference: NdiscRoutePreference::Unknown(2),
            ..base
        };
        assert_eq!(list.push(invalid_preference), Err(invalid_preference));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-rio")]
    fn test_route_information_list_retains_withdrawal_when_full() {
        let route = |index, lifetime| NdiscRouteInformation {
            prefix_len: 64,
            preference: NdiscRoutePreference::Medium,
            route_lifetime: lifetime,
            prefix: Ipv6Address::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0),
        };
        let mut list = RouteInformationList::new();
        for index in 1..=IFACE_MAX_ROUTE_COUNT as u16 {
            list.push(route(index, Duration::from_secs(900))).unwrap();
        }

        let withdrawal = route(0xff, Duration::ZERO);
        assert_eq!(list.push(withdrawal), Ok(()));
        assert_eq!(list.iter().count(), IFACE_MAX_ROUTE_COUNT);
        assert_eq!(list.iter().next(), Some(withdrawal));
        assert!(
            !list
                .iter()
                .any(|entry| entry.prefix == route(1, Duration::ZERO).prefix)
        );
    }
}
