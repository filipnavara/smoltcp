use super::*;

fn parse_ipv6(data: &[u8]) -> crate::wire::Result<Packet<'_>> {
    let ipv6_header = Ipv6Packet::new_checked(data)?;
    let ipv6 = Ipv6Repr::parse(&ipv6_header)?;

    match ipv6.next_header {
        IpProtocol::HopByHop => todo!(),
        IpProtocol::Icmp => todo!(),
        IpProtocol::Igmp => todo!(),
        IpProtocol::Tcp => todo!(),
        IpProtocol::Udp => todo!(),
        IpProtocol::Ipv6Route => todo!(),
        IpProtocol::Ipv6Frag => todo!(),
        IpProtocol::IpSecEsp => todo!(),
        IpProtocol::IpSecAh => todo!(),
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Repr::parse(
                &ipv6.src_addr,
                &ipv6.dst_addr,
                &Icmpv6Packet::new_checked(ipv6_header.payload())?,
                &Default::default(),
            )?;
            Ok(Packet::new_ipv6(ipv6, IpPayload::Icmpv6(icmp)))
        }
        IpProtocol::Ipv6NoNxt => todo!(),
        IpProtocol::Ipv6Opts => todo!(),
        IpProtocol::Unknown(_) => todo!(),
    }
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn any_ip(#[case] medium: Medium) {
    // An empty echo request with destination address fdbe::3, which is not part of the interface
    // address list.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x3, 0x80, 0x0, 0x84, 0x3a, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0003),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let (mut iface, mut sockets, _device) = setup(medium);

    // Add a route to the interface, otherwise, we don't know if the packet is routed localy.
    iface.routes_mut().update(|routes| {
        routes
            .push(crate::iface::Route {
                cidr: IpCidr::Ipv6(Ipv6Cidr::new(
                    Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0),
                    64,
                )),
                via_router: IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001)),
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();
    });

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        None
    );

    // Accept any IP:
    iface.set_any_ip(true);
    assert!(
        iface
            .inner
            .process_ipv6(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::default(),
                &Ipv6Packet::new_checked(&data[..]).unwrap()
            )
            .is_some()
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn multicast_source_address(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn hop_by_hop_skip_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (skipped)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0xf, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn hop_by_hop_discard_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_param_problem(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard + ParamProblem)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_with_multicast(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard (0b11) + ParamProblem)
    // - ICMP echo request
    //
    // In this case, even if the destination address is a multicast address, an ICMPv6 ParamProblem
    // should be transmitted.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn imcp_empty_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x84, 0x3c, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 8,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 0,
            seq_no: 0,
            data: b"",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn icmp_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72,
        0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 42,
                seq_no: 420,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn icmp_echo_reply_as_input(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x81, 0x0, 0x2d, 0x56, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x6f, 0x72, 0x65,
        0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
                ident: 0,
                seq_no: 0,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn unknown_proto_with_multicast_dst_address(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn unknown_proto(#[case] medium: Medium) {
    // Since the destination address is multicast, we should answer with an ICMPv6 message.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndisc_neighbor_advertisement_ethernet(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x9f, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );

    #[cfg(not(feature = "proto-ipv6-rio"))]
    let neighbor_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002);
    #[cfg(feature = "proto-ipv6-rio")]
    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        // RFC 4861 section 7.2.5 does not create a target entry from an
        // advertisement when no solicitation or live mapping preceded it.
        NeighborAnswer::NotFound,
    );
    #[cfg(not(feature = "proto-ipv6-rio"))]
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv6(neighbor_addr), iface.inner.now,),
        NeighborAnswer::Found(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
            0, 0, 0, 0, 0, 1
        ]))),
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndisc_neighbor_advertisement_ethernet_multicast_addr(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0xa0, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                ])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );

    #[cfg(feature = "proto-ipv6-rio")]
    let neighbor_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002);
    #[cfg(not(feature = "proto-ipv6-rio"))]
    let neighbor_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002);
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv6(neighbor_addr), iface.inner.now,),
        NeighborAnswer::NotFound,
    );
}

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn ndisc_neighbor_advertisement_ieee802154(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x28, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x96, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 40,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap()
        ),
        response
    );

    #[cfg(not(feature = "proto-ipv6-rio"))]
    let neighbor_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002);
    #[cfg(feature = "proto-ipv6-rio")]
    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        NeighborAnswer::NotFound,
    );
    #[cfg(not(feature = "proto-ipv6-rio"))]
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv6(neighbor_addr), iface.inner.now,),
        NeighborAnswer::Found(HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(
            &[0, 0, 0, 0, 0, 0, 0, 1]
        ))),
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn delayed_neighbor_advertisements_complete_multiple_pending_resolutions() {
    if crate::config::IFACE_NEIGHBOR_CACHE_COUNT < 2 {
        return;
    }

    let (mut iface, _, _) = setup(Medium::Ethernet);
    let neighbors = [
        Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
        Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 3),
    ];

    for (seconds, neighbor) in neighbors.into_iter().enumerate() {
        iface.inner.now = Instant::from_secs(seconds as i64);
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv6(neighbor),
                &mut iface.fragmenter,
            ),
            Err(DispatchError::NeighborPending)
        );
    }

    let response_at = Instant::from_secs(2);
    iface.inner.now = response_at;
    let local_addr = iface.ipv6_addr().unwrap();
    for (last_octet, neighbor) in [2, 3].into_iter().zip(neighbors) {
        let hardware_addr = EthernetAddress([0x52, 0x54, 0, 0, 0, last_octet]);
        assert!(
            iface
                .inner
                .process_ndisc(
                    Ipv6Repr {
                        src_addr: neighbor,
                        dst_addr: local_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: 0,
                        hop_limit: 255,
                    },
                    NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: neighbor,
                        lladdr: Some(hardware_addr.into()),
                    },
                )
                .is_none()
        );
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(&neighbor.into(), response_at),
            NeighborAnswer::Found(HardwareAddress::Ethernet(hardware_addr))
        );
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_valid_ndisc_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
        target_addr: local_ip_addr,
        lladdr: Some(remote_hw_addr.into()),
    });
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr,
        dst_addr: local_ip_addr.solicited_node(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: solicit.buffer_len(),
    });

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    solicit.emit(
        &remote_ip_addr,
        &local_ip_addr.solicited_node(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
        flags: NdiscNeighborFlags::SOLICITED,
        target_addr: local_ip_addr,
        lladdr: Some(local_hw_addr.into()),
    });

    let ipv6_expected = Ipv6Repr {
        src_addr: local_ip_addr,
        dst_addr: remote_ip_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: icmpv6_expected.buffer_len(),
    };

    // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        Some(EthernetPacket::Ip(Packet::new_ipv6(
            ipv6_expected,
            IpPayload::Icmpv6(icmpv6_expected)
        )))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv6(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-slaac", feature = "medium-ethernet"))]
fn test_router_advertisement() {
    let medium = Medium::Ethernet;
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }
    let prefix_addr = Ipv6Address::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 0);

    let mut device = crate::tests::TestingDevice::new(medium);
    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;

    // RIO adds an eight-byte SLLA to this RA. Keep the backing frame exact
    // sized in both configurations because ICMPv6 emission checksums the
    // entire supplied payload buffer.
    #[cfg(feature = "proto-ipv6-rio")]
    let mut eth_bytes = vec![0u8; 110];
    #[cfg(not(feature = "proto-ipv6-rio"))]
    let mut eth_bytes = vec![0u8; 102];

    // Create mac addresses with derived link local addresses
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let ll_prefix = Ipv6Cidr::new(Ipv6Cidr::LINK_LOCAL_PREFIX.address(), 64);
    let local_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(local_hw_addr)).unwrap();
    let remote_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(remote_hw_addr)).unwrap();

    // Create config with slaac enabled
    let mut config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => HardwareAddress::Ethernet(local_hw_addr),
        _ => panic!("Not supported"),
    });
    config.slaac = true;

    // Set up interface with link local address
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::Ipv6(local_ip_addr)).unwrap();
    });
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6-rio"))]
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 0, 2, 1))
        .unwrap();

    let mut sockets = SocketSet::new(vec![]);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    let transmitted: std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> =
        recv_icmpv6(&mut device, Instant::ZERO)
            .into_iter()
            .filter(|packet| {
                // Filter for router solicitations
                packet.dst_addr() == IPV6_LINK_LOCAL_ALL_ROUTERS
            })
            .collect();

    assert_eq!(transmitted.len(), 1);

    for ipv6_packet in transmitted.into_iter() {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        if ipv6_repr.dst_addr == IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS {
            continue; // Skip MLD reports
        }
        let icmpv6_packet = Icmpv6Packet::new_checked(ipv6_packet.payload()).unwrap();
        let icmp_repr = Icmpv6Repr::parse(
            &ipv6_repr.src_addr,
            &ipv6_repr.dst_addr,
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        assert_eq!(
            icmp_repr,
            Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
                lladdr: Some(local_hw_addr.into()),
            })
        );

        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_ROUTERS);
        println!("repr {:?}", icmp_repr);
    }

    // Craft the router advertisement
    let mut prefix_information = NdiscPrefixInformation {
        prefix: prefix_addr,
        prefix_len: 64,
        flags: NdiscPrefixInfoFlags::ADDRCONF,
        valid_lifetime: Duration::from_secs(600),
        preferred_lifetime: Duration::from_secs(300),
    };
    let mut advertisement = NdiscRepr::RouterAdvert {
        hop_limit: 255,
        flags: NdiscRouterFlags::empty(),
        #[cfg(feature = "proto-ipv6-rio")]
        preference: NdiscRoutePreference::Medium,
        router_lifetime: Duration::from_secs(600),
        reachable_time: Duration::from_secs(0),
        retrans_time: Duration::from_secs(0),
        lladdr: {
            #[cfg(feature = "proto-ipv6-rio")]
            {
                Some(remote_hw_addr.into())
            }
            #[cfg(not(feature = "proto-ipv6-rio"))]
            {
                None
            }
        },
        mtu: None,
        prefix_info: Some(prefix_information),
        #[cfg(feature = "proto-ipv6-rio")]
        route_info: NdiscRouteInformationList::new(),
    };
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr.address(),
        dst_addr: local_ip_addr.address(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255,
        payload_len: advertisement.buffer_len(),
    });
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    #[cfg(feature = "proto-ipv6-rio")]
    device.rx_queue.push_back(frame.into_inner().to_vec());
    #[cfg(not(feature = "proto-ipv6-rio"))]
    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    // RIO routes must be visible to egress in the poll that receives the RA.
    // The feature-off branch retains the original pre-ingress synchronization
    // sequence above.
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // An unrelated IPv4 route must not prevent synchronization of an IPv6
    // route learned from a Router Advertisement.
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6-rio"))]
    iface.routes_mut().update(|routes| {
        assert!(routes.iter().any(|route| {
            route.cidr == IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0)
                && route.via_router == IpAddress::Ipv6(remote_ip_addr.address())
        }));
    });
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6-rio"))]
    iface.routes_mut().remove_default_ipv4_route();

    // Expect to have these two addresses after the router advertisement
    let expected_addrs = [
        IpCidr::Ipv6(local_ip_addr),
        IpCidr::Ipv6(Ipv6Cidr::new(
            Ipv6Address::new(0x2001, 0xdb8, 0x3, 0x0, 0x2, 0x2ff, 0xfe02, 0x202),
            64,
        )),
    ];
    for (generated, expected) in iface.ip_addrs().iter().zip(expected_addrs.iter()) {
        assert_eq!(generated, expected);
    }
    #[cfg(feature = "proto-ipv6-rio")]
    {
        // The same poll also synchronizes the new SLAAC address. That internal
        // address update must retain the mapping and IsRouter state supplied
        // by the RA rather than flushing the information it just learned.
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(&IpAddress::Ipv6(remote_ip_addr.address()), Instant::ZERO,),
            NeighborAnswer::Found(HardwareAddress::Ethernet(remote_hw_addr))
        );
        assert!(
            iface
                .inner
                .neighbor_cache
                .is_router(&remote_ip_addr.address(), Instant::ZERO)
        );
    }
    // Verify the pushed route matches expected
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
        assert_eq!(
            route[0].cidr,
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0)
        );
        assert_eq!(
            route[0].via_router,
            IpAddress::Ipv6(remote_ip_addr.address())
        );
        assert_eq!(route[0].preferred_until, None);
        #[cfg(feature = "proto-ipv6-rio")]
        assert_eq!(route[0].expires_at, Some(Instant::from_secs(600)));
        #[cfg(not(feature = "proto-ipv6-rio"))]
        assert_eq!(route[0].expires_at, None);
    });

    // Craft a router advertisement with zero lifetime for the prefix
    // to remove the prefix, but retain the route
    prefix_information.valid_lifetime = Duration::ZERO;
    prefix_information.preferred_lifetime = Duration::ZERO;
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ..
    } = advertisement
    {
        *prefix_info = Some(prefix_information);
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(10);

    iface.poll(now, &mut device, &mut sockets);
    assert_eq!(iface.ip_addrs().len(), 1);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
    });

    // Craft router advertisement with zero router lifetime
    // to remove the route
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ref mut router_lifetime,
        ..
    } = advertisement
    {
        *prefix_info = None;
        *router_lifetime = Duration::ZERO;
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(20);
    iface.poll(now, &mut device, &mut sockets);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 0);
    });
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_router_advertisement_route_info() {
    let medium = Medium::Ethernet;
    // Prefix of a Thread mesh network advertised by a Thread Border Router
    // through a Route Information Option (RFC 4191).
    let thread_prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let thread_cidr = IpCidr::new(IpAddress::Ipv6(thread_prefix), 64);

    let mut device = crate::tests::TestingDevice::new(medium);

    // Ethernet header + IPv6 header + router advertisement header + RIO
    let mut eth_bytes = vec![0u8; 14 + 40 + 16 + 16];

    // Create mac addresses with derived link local addresses
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let ll_prefix = Ipv6Cidr::new(Ipv6Cidr::LINK_LOCAL_PREFIX.address(), 64);
    let local_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(local_hw_addr)).unwrap();
    let remote_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(remote_hw_addr)).unwrap();

    // Create config with slaac enabled
    let mut config = Config::new(HardwareAddress::Ethernet(local_hw_addr));
    config.slaac = true;

    // Set up interface with link local address
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::Ipv6(local_ip_addr)).unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Craft a router advertisement carrying a route information option
    let route_information = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::High,
        route_lifetime: Duration::from_secs(1800),
        prefix: thread_prefix,
    };
    let mut advertisement = NdiscRepr::RouterAdvert {
        hop_limit: 255,
        flags: NdiscRouterFlags::empty(),
        preference: NdiscRoutePreference::Medium,
        router_lifetime: Duration::from_secs(600),
        reachable_time: Duration::from_secs(0),
        retrans_time: Duration::from_secs(0),
        lladdr: None,
        mtu: None,
        prefix_info: None,
        route_info: route_information.try_into().unwrap(),
    };
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr.address(),
        dst_addr: local_ip_addr.address(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255,
        payload_len: advertisement.buffer_len(),
    });
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    device.rx_queue.push_back(frame.into_inner().to_vec());
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Both the default route and the RIO-learned route to the Thread prefix
    // must be installed via the advertising router.
    iface.routes_mut().update(|routes| {
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|route| {
            route.cidr == thread_cidr
                && route.via_router == IpAddress::Ipv6(remote_ip_addr.address())
        }));
        assert!(routes.iter().any(|route| {
            route.cidr == IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0)
                && route.via_router == IpAddress::Ipv6(remote_ip_addr.address())
        }));
    });

    // Craft a router advertisement with zero route lifetime to remove the
    // RIO-learned route, but retain the default route
    if let NdiscRepr::RouterAdvert {
        ref mut route_info, ..
    } = advertisement
    {
        let mut expired = route_information;
        expired.route_lifetime = Duration::ZERO;
        *route_info = expired.try_into().unwrap();
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    let now = Instant::from_secs(10);
    device.rx_queue.push_back(frame.into_inner().to_vec());
    iface.poll(now, &mut device, &mut sockets);

    iface.routes_mut().update(|routes| {
        assert_eq!(routes.len(), 1);
        assert!(!routes.iter().any(|route| route.cidr == thread_cidr));
    });
}

#[cfg(all(
    feature = "proto-ipv6-rio",
    feature = "medium-ethernet",
    feature = "socket-udp"
))]
struct SingleTxDevice {
    inner: crate::tests::TestingDevice,
    tx_available: bool,
}

#[cfg(all(
    feature = "proto-ipv6-rio",
    feature = "medium-ethernet",
    feature = "socket-udp"
))]
impl SingleTxDevice {
    fn new(inner: crate::tests::TestingDevice) -> Self {
        Self {
            inner,
            tx_available: true,
        }
    }

    fn replenish(&mut self) {
        self.tx_available = true;
    }
}

#[cfg(all(
    feature = "proto-ipv6-rio",
    feature = "medium-ethernet",
    feature = "socket-udp"
))]
impl Device for SingleTxDevice {
    type RxToken<'a> = crate::tests::RxToken;
    type TxToken<'a> = crate::tests::TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        None
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if !self.tx_available {
            return None;
        }
        self.tx_available = false;
        self.inner.transmit(timestamp)
    }
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_router_advertisement_route_preference() {
    let (mut iface, _, mut device) = setup(Medium::Ethernet);
    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let cidr = IpCidr::new(IpAddress::Ipv6(prefix), 64);
    let low_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let high_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    let mut route_info = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::Low,
        route_lifetime: Duration::from_secs(1800),
        prefix,
    };

    iface.inner.slaac.process_advertisement(
        &low_router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);
    iface.routes_mut().update(|routes| {
        assert!(routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(low_router)
        }));
    });

    route_info.preference = NdiscRoutePreference::High;
    route_info.route_lifetime = Duration::from_secs(600);
    iface.inner.slaac.process_advertisement(
        &high_router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);
    iface.routes_mut().update(|routes| {
        assert!(routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(high_router)
        }));
        assert!(routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(low_router)
        }));
    });

    let destination = IpAddress::Ipv6(Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        iface.inner.route(&destination, Instant::ZERO),
        Some(high_router.into())
    );

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, Instant::from_secs(seconds));
    }
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(3)),
        Some(low_router.into())
    );

    route_info.route_lifetime = Duration::from_secs(900);
    iface.inner.slaac.process_advertisement(
        &high_router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::from_secs(3),
    );
    // This RA only refreshes the learned route's lifetime. Reconciliation must
    // preserve independent failed-router evidence so the fallback stays active.
    iface.poll_maintenance(Instant::from_secs(3));
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(3)),
        Some(low_router.into())
    );

    assert_eq!(
        iface
            .inner
            .route_with_rio_probes(&destination, Instant::from_secs(3)),
        Some(low_router.into())
    );
    let recovery_at = Instant::from_secs(63);
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .router_resolution_poll_at(Instant::from_secs(3)),
        Some(recovery_at)
    );

    iface.inner.now = recovery_at;
    iface.ndisc_router_probe_egress(&mut device);
    let frame_bytes = device.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(frame_bytes.as_slice()).unwrap();
    let ipv6_packet = Ipv6Packet::new_checked(frame.payload()).unwrap();
    let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
    let icmpv6_repr = Icmpv6Repr::parse(
        &ipv6_repr.src_addr,
        &ipv6_repr.dst_addr,
        &Icmpv6Packet::new_checked(ipv6_packet.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(
        icmpv6_repr,
        Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: high_router,
            lladdr: Some(EthernetAddress([0x02; 6]).into()),
        })
    );
    // The recovery NS must not make data select the failed router again;
    // only a neighbor response is evidence that it recovered.
    assert_eq!(
        iface.inner.route(&destination, recovery_at),
        Some(low_router.into())
    );

    let local_addr = iface.ipv6_addr().unwrap();
    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: high_router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::ROUTER | NdiscNeighborFlags::SOLICITED,
                    target_addr: high_router,
                    lladdr: None,
                },
            )
            .is_none()
    );
    // Without a TLLA, an incomplete/no-mapping NA cannot complete NUD.
    assert_eq!(
        iface.inner.route(&destination, recovery_at),
        Some(low_router.into())
    );

    iface.inner.neighbor_cache.fill(
        high_router.into(),
        HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0, 0, 0, 3])),
        recovery_at,
    );
    // Learning or refreshing a link-layer mapping is not RFC 4861
    // reachability evidence, so an ordinary cache fill must leave the failed
    // router behind the reachable lower-preference alternative.
    assert_eq!(
        iface.inner.route(&destination, recovery_at),
        Some(low_router.into())
    );

    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: high_router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::ROUTER | NdiscNeighborFlags::SOLICITED,
                    target_addr: high_router,
                    lladdr: Some(EthernetAddress([0x52, 0x54, 0, 0, 0, 4]).into()),
                },
            )
            .is_none()
    );
    // Override=0 protects a different cached TLLA and cannot be treated
    // as reachability confirmation.
    assert_eq!(
        iface.inner.route(&destination, recovery_at),
        Some(low_router.into())
    );
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&high_router.into(), recovery_at),
        NeighborAnswer::Found(HardwareAddress::Ethernet(EthernetAddress([
            0x52, 0x54, 0, 0, 0, 3
        ])))
    );

    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: high_router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::ROUTER | NdiscNeighborFlags::SOLICITED,
                    target_addr: high_router,
                    lladdr: None,
                },
            )
            .is_none()
    );
    // A no-TLLA response is usable once the target mapping already exists.
    assert_eq!(
        iface.inner.route(&destination, recovery_at),
        Some(high_router.into())
    );

    for _ in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, recovery_at);
    }
    let stale_at = Instant::from_secs(64);
    assert_eq!(
        iface.inner.route(&destination, stale_at),
        Some(low_router.into())
    );
    iface.inner.now = stale_at;
    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: high_router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::ROUTER | NdiscNeighborFlags::OVERRIDE,
                    target_addr: high_router,
                    lladdr: Some(EthernetAddress([0x52, 0x54, 0, 0, 0, 5]).into()),
                },
            )
            .is_none()
    );
    // An accepted unsolicited TLLA change moves an RFC 4861 neighbor to
    // STALE. It is not a reachability confirmation, but it is no longer known
    // unreachable and must be eligible for RFC 4191 selection again.
    assert_eq!(
        iface.inner.route(&destination, stale_at),
        Some(high_router.into())
    );

    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: high_router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::SOLICITED,
                    target_addr: high_router,
                    lladdr: None,
                },
            )
            .is_none()
    );
    // An accepted R=0 advertisement says this node stopped routing.
    // RFC 4861 requires learned routes through it to disappear before the
    // next queued packet can use the node again.
    assert_eq!(
        iface.inner.route(&destination, stale_at),
        Some(low_router.into())
    );
    iface.routes_mut().update(|routes| {
        assert!(!routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(high_router)
        }));
    });

    iface.poll_maintenance(Instant::from_secs(600));
    iface.routes_mut().update(|routes| {
        assert!(routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(low_router)
        }));
        assert!(!routes.iter().any(|route| {
            route.cidr == cidr && route.via_router == IpAddress::Ipv6(high_router)
        }));
    });

    iface.routes_mut().update(|routes| {
        routes
            .retain(|route| route.cidr != cidr || route.via_router != IpAddress::Ipv6(low_router));
    });
    // The public route table is authoritative. Removing the surviving
    // learned route must stop forwarding immediately instead of leaving a
    // hidden SLAAC candidate active until the next maintenance pass.
    assert_eq!(iface.inner.route(&destination, recovery_at), None);
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_untracked_r0_neighbor_advertisement_keeps_learned_route() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    iface.inner.slaac.process_advertisement(
        &router,
        Duration::from_secs(600),
        NdiscRoutePreference::High,
        None,
        NdiscRouteInformationList::new(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);
    assert_eq!(
        iface.inner.route(&destination, Instant::ZERO),
        Some(router.into())
    );
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&router.into(), Instant::ZERO),
        NeighborAnswer::NotFound
    );

    let local_addr = iface.ipv6_addr().unwrap();
    for last_octet in [2, 3] {
        assert!(
            iface
                .inner
                .process_ndisc(
                    Ipv6Repr {
                        src_addr: router,
                        dst_addr: local_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: 0,
                        hop_limit: 255,
                    },
                    NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::empty(),
                        target_addr: router,
                        lladdr: Some(EthernetAddress([0x52, 0x54, 0, 0, 0, last_octet]).into(),),
                    },
                )
                .is_none()
        );
        // Repeated no-entry advertisements must remain side-effect free; the
        // first one cannot bootstrap cache state that authorizes the second.
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(&router.into(), Instant::ZERO),
            NeighborAnswer::NotFound
        );
        assert_eq!(
            iface.inner.route(&destination, Instant::ZERO),
            Some(router.into())
        );
    }

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(router, Instant::from_secs(seconds));
    }
    let failed_at = Instant::from_secs(3);
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router_unreachable(&router, failed_at)
    );
    iface.inner.now = failed_at;
    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::empty(),
                    target_addr: router,
                    lladdr: Some(EthernetAddress([0x52, 0x54, 0, 0, 0, 4]).into()),
                },
            )
            .is_none()
    );
    // A completed failed-resolution record is routing evidence, not a live
    // Neighbor Cache entry. It cannot authorize a later unsolicited R=0.
    assert_eq!(
        iface.inner.route(&destination, failed_at),
        Some(router.into())
    );
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&router.into(), failed_at),
        NeighborAnswer::NotFound
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_outstanding_r0_neighbor_advertisement_withdraws_learned_route() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    iface.inner.slaac.process_advertisement(
        &router,
        Duration::from_secs(600),
        NdiscRoutePreference::High,
        None,
        NdiscRouteInformationList::new(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(router, Instant::from_secs(seconds));
    }
    let failed_at = Instant::from_secs(3);
    iface.inner.now = failed_at;
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router_unreachable(&router, failed_at)
    );
    assert_eq!(
        iface
            .inner
            .lookup_hardware_addr(MockTxToken, &destination, &mut iface.fragmenter,),
        Err(DispatchError::NeighborPending)
    );

    let local_addr = iface.ipv6_addr().unwrap();
    assert!(
        iface
            .inner
            .process_ndisc(
                Ipv6Repr {
                    src_addr: router,
                    dst_addr: local_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: 0,
                    hop_limit: 255,
                },
                NdiscRepr::NeighborAdvert {
                    flags: NdiscNeighborFlags::SOLICITED,
                    target_addr: router,
                    lladdr: Some(EthernetAddress([0x52, 0x54, 0, 0, 0, 2]).into()),
                },
            )
            .is_none()
    );

    // A new ordinary lookup can revisit a router after its earlier resolution
    // failed. Its actually dispatched NS creates a fresh INCOMPLETE entry, so
    // the solicited R=0 response is still a TRUE-to-FALSE transition.
    assert_eq!(iface.inner.route(&destination, failed_at), None);
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_ra_and_ns_slla_changes_move_failed_router_to_stale() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.slaac_enabled = true;
    let high_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let low_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let local_addr = iface.ipv6_addr().unwrap();
    let high_hardware_a = EthernetAddress([0x52, 0x54, 0, 0, 0, 2]);
    let high_hardware_b = EthernetAddress([0x52, 0x54, 0, 0, 0, 4]);
    let high_hardware_c = EthernetAddress([0x52, 0x54, 0, 0, 0, 5]);
    let router_advert = |lladdr| NdiscRepr::RouterAdvert {
        hop_limit: 255,
        flags: NdiscRouterFlags::empty(),
        preference: NdiscRoutePreference::High,
        router_lifetime: Duration::from_secs(600),
        reachable_time: Duration::ZERO,
        retrans_time: Duration::ZERO,
        lladdr: Some(lladdr),
        mtu: None,
        prefix_info: None,
        route_info: NdiscRouteInformationList::new(),
    };
    let high_ip_repr = Ipv6Repr {
        src_addr: high_router,
        dst_addr: IPV6_LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Icmpv6,
        payload_len: 0,
        hop_limit: 255,
    };

    let _ = iface
        .inner
        .process_ndisc(high_ip_repr, router_advert(high_hardware_a.into()));
    iface.inner.slaac.process_advertisement(
        &low_router,
        Duration::from_secs(600),
        NdiscRoutePreference::Low,
        None,
        NdiscRouteInformationList::new(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);
    assert_eq!(
        iface.inner.route(&destination, Instant::ZERO),
        Some(high_router.into())
    );

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, Instant::from_secs(seconds));
    }
    iface.inner.now = Instant::from_secs(3);
    assert_eq!(
        iface.inner.route(&destination, iface.inner.now),
        Some(low_router.into())
    );

    let _ = iface
        .inner
        .process_ndisc(high_ip_repr, router_advert(high_hardware_a.into()));
    iface.poll_maintenance(Instant::from_secs(3));
    // An RA with the same SLLA refreshes IsRouter but provides no new NUD
    // evidence, so the known-unreachable router must remain suppressed.
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(3)),
        Some(low_router.into())
    );

    let _ = iface
        .inner
        .process_ndisc(high_ip_repr, router_advert(high_hardware_b.into()));
    iface.poll_maintenance(Instant::from_secs(3));
    // A changed RA mapping enters STALE rather than REACHABLE. This simplified
    // cache represents STALE as unknown, making the preferred router eligible
    // again without treating the RA as a reachability confirmation.
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(3)),
        Some(high_router.into())
    );
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router(&high_router, Instant::from_secs(3))
    );

    for seconds in 3..6 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, Instant::from_secs(seconds));
    }
    iface.inner.now = Instant::from_secs(6);
    assert_eq!(
        iface.inner.route(&destination, iface.inner.now),
        Some(low_router.into())
    );

    let solicit = |lladdr| NdiscRepr::NeighborSolicit {
        target_addr: local_addr,
        lladdr: Some(lladdr),
    };
    let solicit_ip_repr = Ipv6Repr {
        src_addr: high_router,
        dst_addr: local_addr.solicited_node(),
        next_header: IpProtocol::Icmpv6,
        payload_len: 0,
        hop_limit: 255,
    };
    let _ = iface
        .inner
        .process_ndisc(solicit_ip_repr, solicit(high_hardware_b.into()));
    // An NS carries no router-role information and the unchanged mapping is
    // not NUD evidence, so both IsRouter and the failed state are preserved.
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router(&high_router, iface.inner.now)
    );
    assert_eq!(
        iface.inner.route(&destination, iface.inner.now),
        Some(low_router.into())
    );

    let _ = iface
        .inner
        .process_ndisc(solicit_ip_repr, solicit(high_hardware_c.into()));
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router(&high_router, iface.inner.now)
    );
    assert_eq!(
        iface.inner.route(&destination, iface.inner.now),
        Some(high_router.into())
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_router_advertisement_ignores_unusable_slla_but_keeps_route_info() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.slaac_enabled = true;
    let router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let prefix = Ipv6Address::new(0x2001, 0xdb8, 0x42, 0, 0, 0, 0, 0);
    let route_info = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::High,
        route_lifetime: Duration::from_secs(600),
        prefix,
    };
    let advertisement = NdiscRepr::RouterAdvert {
        hop_limit: 64,
        flags: NdiscRouterFlags::empty(),
        preference: NdiscRoutePreference::Medium,
        router_lifetime: Duration::ZERO,
        reachable_time: Duration::ZERO,
        retrans_time: Duration::ZERO,
        lladdr: Some(EthernetAddress([0xff; 6]).into()),
        mtu: None,
        prefix_info: None,
        route_info: route_info.try_into().unwrap(),
    };
    let ip_repr = Ipv6Repr {
        src_addr: router,
        dst_addr: IPV6_LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Icmpv6,
        payload_len: advertisement.buffer_len(),
        hop_limit: 255,
    };

    let _ = iface.inner.process_ndisc(ip_repr, advertisement);
    iface.poll_maintenance(Instant::ZERO);

    // The unusable SLLA cannot create a mapping, but that independent option
    // must not suppress the valid RIO carried by the same advertisement.
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&router.into(), Instant::ZERO),
        NeighborAnswer::NotFound
    );
    assert_eq!(
        iface.inner.route(
            &IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0x42, 0, 0, 0, 0, 1)),
            Instant::ZERO,
        ),
        Some(router.into())
    );
}

#[test]
#[cfg(all(
    feature = "proto-ipv6-rio",
    feature = "medium-ethernet",
    feature = "socket-udp"
))]
fn test_recovery_probe_has_bounded_fairness_after_application_packet() {
    use crate::socket::udp;

    let (mut iface, mut sockets, mut backing_device) = setup(Medium::Ethernet);
    // Drain membership reports before imposing the one-token budget; they are
    // unrelated to the application-versus-recovery ordering under test.
    iface.poll_egress(Instant::ZERO, &mut backing_device, &mut sockets);
    backing_device.tx_queue.clear();
    let mut device = SingleTxDevice::new(backing_device);

    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let probe_destination = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1);
    let app_destination = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let high_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let low_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    let route_info = |prefix, preference, route_lifetime| NdiscRouteInformation {
        prefix_len: 64,
        preference,
        route_lifetime,
        prefix,
    };

    for (router, preference) in [
        (high_router, NdiscRoutePreference::High),
        (low_router, NdiscRoutePreference::Low),
    ] {
        iface.inner.slaac.process_advertisement(
            &router,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info(prefix, preference, Duration::from_secs(600))
                .try_into()
                .unwrap(),
            Instant::ZERO,
        );
    }
    iface.poll_maintenance(Instant::ZERO);
    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, Instant::from_secs(seconds));
    }
    assert_eq!(
        iface
            .inner
            .route_with_rio_probes(&probe_destination.into(), Instant::from_secs(3)),
        Some(low_router.into())
    );
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .router_resolution_poll_at(Instant::from_secs(4)),
        Some(Instant::from_secs(63))
    );
    iface.inner.neighbor_cache.fill(
        app_destination.into(),
        HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0, 0, 0, 4])),
        Instant::from_secs(4),
    );

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 32]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 32]);
    let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
    socket.bind(1234).unwrap();
    socket
        .send_slice(b"first", IpEndpoint::new(app_destination.into(), 4321))
        .unwrap();
    let handle = sockets.add(socket);

    let recovery_at = Instant::from_secs(63);
    let requested_router = iface
        .inner
        .neighbor_cache
        .router_probe_required(recovery_at)
        .unwrap();
    assert_eq!(requested_router, high_router);
    assert!(
        iface
            .inner
            .neighbor_cache
            .router_probe_destinations(requested_router)
            .any(|stored| stored == probe_destination)
    );
    iface.poll_egress(recovery_at, &mut device, &mut sockets);
    let frame_bytes = device.inner.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(frame_bytes.as_slice()).unwrap();
    let packet = Ipv6Packet::new_checked(frame.payload()).unwrap();
    assert_eq!(
        Ipv6Repr::parse(&packet).unwrap().next_header,
        IpProtocol::Udp
    );
    assert!(device.inner.tx_queue.is_empty());

    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(b"second", IpEndpoint::new(app_destination.into(), 4321))
        .unwrap();
    device.replenish();
    iface.poll_egress(recovery_at, &mut device, &mut sockets);
    let frame_bytes = device.inner.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(frame_bytes.as_slice()).unwrap();
    let packet = Ipv6Packet::new_checked(frame.payload()).unwrap();
    let ipv6 = Ipv6Repr::parse(&packet).unwrap();
    let probe = Icmpv6Repr::parse(
        &ipv6.src_addr,
        &ipv6.dst_addr,
        &Icmpv6Packet::new_checked(packet.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(
        probe,
        Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: high_router,
            lladdr: Some(EthernetAddress([0x02; 6]).into()),
        })
    );
    assert!(sockets.get::<udp::Socket>(handle).send_queue() > 0);

    device.replenish();
    iface.poll_egress(recovery_at, &mut device, &mut sockets);
    let frame_bytes = device.inner.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(frame_bytes.as_slice()).unwrap();
    let packet = Ipv6Packet::new_checked(frame.payload()).unwrap();
    assert_eq!(
        Ipv6Repr::parse(&packet).unwrap().next_header,
        IpProtocol::Udp
    );
    assert_eq!(sockets.get::<udp::Socket>(handle).send_queue(), 0);
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_router_resolution_capacity_preserves_reachable_fallback() {
    if crate::config::IFACE_MAX_ROUTE_COUNT < 3 {
        return;
    }

    let (mut iface, _, _) = setup(Medium::Ethernet);
    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1));
    let high_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let medium_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    let low_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 4);

    for (router, preference) in [
        (high_router, NdiscRoutePreference::High),
        (medium_router, NdiscRoutePreference::Medium),
        (low_router, NdiscRoutePreference::Low),
    ] {
        let route_info = NdiscRouteInformation {
            prefix_len: 64,
            preference,
            route_lifetime: Duration::from_secs(600),
            prefix,
        };
        iface.inner.slaac.process_advertisement(
            &router,
            Duration::ZERO,
            NdiscRoutePreference::Medium,
            None,
            route_info.try_into().unwrap(),
            Instant::ZERO,
        );
        iface.poll_maintenance(Instant::ZERO);
    }
    assert_eq!(
        iface.inner.route(&destination, Instant::ZERO),
        Some(high_router.into())
    );

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(high_router, Instant::from_secs(seconds));
    }
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(3)),
        Some(medium_router.into())
    );

    for seconds in 3..6 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(medium_router, Instant::from_secs(seconds));
    }
    // Forgetting the first failed router when the resolution store fills
    // makes it eligible again and prevents reaching this lower preference.
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(6)),
        Some(low_router.into())
    );
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router_unreachable(&high_router, Instant::from_secs(6))
    );
    assert!(
        iface
            .inner
            .neighbor_cache
            .is_router_unreachable(&medium_router, Instant::from_secs(6))
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_unreachable_rio_uses_configured_fallback_and_requests_probe() {
    let (mut iface, _, mut device) = setup(Medium::Ethernet);
    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 1));
    let learned_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let configured_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);

    iface
        .routes_mut()
        .add_default_ipv6_route(configured_router)
        .unwrap();
    let mut route_info = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::High,
        route_lifetime: Duration::from_secs(600),
        prefix,
    };
    iface.inner.slaac.process_advertisement(
        &learned_router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);

    for seconds in 0..3 {
        iface
            .inner
            .neighbor_cache
            .record_router_probe(learned_router, Instant::from_secs(seconds));
    }
    let now = Instant::from_secs(3);
    iface.inner.neighbor_cache.fill(
        configured_router.into(),
        HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0, 0, 0, 3])),
        now,
    );
    iface.inner.now = now;

    // Read-only socket readiness and actual dispatch must agree on the
    // configured fallback, or a cached next hop can be held unnecessarily.
    assert_eq!(
        iface.inner.route(&destination, now),
        Some(configured_router.into())
    );
    assert!(iface.inner.has_neighbor(&destination));
    assert_eq!(
        iface.inner.route_with_rio_probes(&destination, now),
        Some(configured_router.into())
    );
    assert_eq!(
        iface.inner.neighbor_cache.router_resolution_poll_at(now),
        Some(Instant::from_secs(63))
    );

    route_info.route_lifetime = Duration::ZERO;
    iface.inner.slaac.process_advertisement(
        &learned_router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::from_secs(4),
    );
    // This test invokes the internal SLAAC state machine directly,
    // bypassing the normal post-ingress synchronization in `poll()`.
    iface.poll_maintenance(Instant::from_secs(4));
    iface.inner.now = Instant::from_secs(63);
    iface.ndisc_router_probe_egress(&mut device);
    // Keep the RA's router lifetime at zero so this test isolates the
    // learned /64. Once that route is withdrawn, no learned route remains to
    // authorize the delayed RFC 4191 recovery probe.
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .router_resolution_state(&learned_router, Instant::from_secs(63)),
        crate::iface::neighbor::RouterResolutionState::Unknown
    );
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_slaac_withdrawal_preserves_static_route() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let cidr = IpCidr::new(prefix.into(), 64);
    let router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let mut route_info = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::High,
        route_lifetime: Duration::from_secs(1800),
        prefix,
    };

    iface.routes_mut().update(|routes| {
        routes
            .push(crate::iface::Route {
                cidr,
                via_router: router.into(),
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();
    });
    iface.inner.slaac.process_advertisement(
        &router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);

    route_info.route_lifetime = Duration::ZERO;
    iface.inner.slaac.process_advertisement(
        &router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::from_secs(1),
    );
    iface.poll_maintenance(Instant::from_secs(1));

    iface.routes_mut().update(|routes| {
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cidr, cidr);
        assert_eq!(routes[0].via_router, router.into());
        assert_eq!(routes[0].expires_at, None);
    });
}

#[test]
#[cfg(all(feature = "proto-ipv6-rio", feature = "medium-ethernet"))]
fn test_slaac_withdrawal_preserves_application_copy_of_learned_route() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let prefix = Ipv6Address::new(0xfd00, 0xdb8, 0, 0, 0, 0, 0, 0);
    let cidr = IpCidr::new(prefix.into(), 64);
    let router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let mut route_info = NdiscRouteInformation {
        prefix_len: 64,
        preference: NdiscRoutePreference::High,
        route_lifetime: Duration::from_secs(1800),
        prefix,
    };

    iface.inner.slaac.process_advertisement(
        &router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);

    // Add an exact application copy in a separate public-table update. With
    // two indistinguishable occurrences, ownership must be dropped rather
    // than guessed.
    iface.routes_mut().update(|routes| {
        let learned = *routes
            .iter()
            .find(|route| route.cidr == cidr && route.via_router == router.into())
            .unwrap();
        routes.push(learned).unwrap();
    });
    iface.routes_mut().update(|routes| {
        routes.remove(
            routes
                .iter()
                .position(|route| route.cidr == cidr && route.via_router == router.into())
                .unwrap(),
        );
    });

    route_info.route_lifetime = Duration::ZERO;
    iface.inner.slaac.process_advertisement(
        &router,
        Duration::ZERO,
        NdiscRoutePreference::Medium,
        None,
        route_info.try_into().unwrap(),
        Instant::from_secs(1),
    );
    iface.poll_maintenance(Instant::from_secs(1));

    iface.routes_mut().update(|routes| {
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cidr, cidr);
        assert_eq!(routes[0].via_router, router.into());
    });
}

#[test]
#[cfg(all(
    not(feature = "proto-ipv6-rio"),
    feature = "proto-ipv6-slaac",
    feature = "medium-ethernet"
))]
fn test_slaac_refresh_preserves_feature_off_route_order() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let learned_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let configured_router = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    let destination = IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));

    iface.inner.slaac.process_advertisement(
        &learned_router,
        Duration::from_secs(600),
        None,
        Instant::ZERO,
    );
    iface.poll_maintenance(Instant::ZERO);
    iface
        .routes_mut()
        .add_default_ipv6_route(configured_router)
        .unwrap();
    assert_eq!(
        iface.inner.route(&destination, Instant::ZERO),
        Some(configured_router.into())
    );

    iface.inner.slaac.process_advertisement(
        &learned_router,
        Duration::from_secs(600),
        None,
        Instant::from_secs(1),
    );
    iface.poll_maintenance(Instant::from_secs(1));

    // A lifetime-only refresh has no public metadata to update when RIO is
    // disabled. Avoiding a remove-and-append keeps the application's later
    // equal-prefix route in the same precedence position.
    assert_eq!(
        iface.inner.route(&destination, Instant::from_secs(1)),
        Some(configured_router.into())
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn test_solicited_node_addrs(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);
    let mut new_addrs = heapless::Vec::<IpCidr, IFACE_MAX_ADDR_COUNT>::new();
    new_addrs
        .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64))
        .unwrap();
    new_addrs
        .push(IpCidr::new(
            IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff),
            64,
        ))
        .unwrap();
    iface.update_ip_addrs(|addrs| {
        new_addrs.extend(addrs.to_vec());
        *addrs = new_addrs;
    });
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002))
    );
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff))
    );
    assert!(
        !iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-udp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-udp", feature = "medium-ethernet"))]
#[case(Medium::Ieee802154)]
#[cfg(all(feature = "socket-udp", feature = "medium-ieee802154"))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::IPV6_MIN_MTU as MIN_MTU;
    use crate::wire::Icmpv6DstUnreachable;
    const MAX_PAYLOAD_LEN: usize = 1192;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    // UDP packet that if not tructated will cause a icmp port unreachable reply
    // to exceed the minimum mtu bytes in length.
    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + MAX_PAYLOAD_LEN];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        MAX_PAYLOAD_LEN,
        |buf| fill_slice(buf, 0x2a),
        &ChecksumCapabilities::default(),
    );

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
        reason: Icmpv6DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };

    let expected_ip_repr = Ipv6Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 64,
        payload_len: expected_icmp_repr.buffer_len(),
    };

    assert_eq!(
        expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
        MIN_MTU
    );

    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr.into(),
            payload,
        ),
        Some(Packet::new_ipv6(
            expected_ip_repr,
            IpPayload::Icmpv6(expected_icmp_repr)
        ))
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address() {
    let (mut iface, _, _) = setup(Medium::Ip);

    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const OWN_UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 2);
    const OWN_GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 1);

    // List of addresses of the interface:
    //   fe80::1/64
    //   fd00::201:1:1:1:2/64
    //   fd01::201:1:1:1:2/64
    //   2001:db8:3::1/64
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_GLOBAL_UNICAST_ADDR1, 64)))
            .unwrap();
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fd00::201:1:1:1:2
    //   fd01::201:1:1:1:1 -> fd01::201:1:1:1:2
    //   fd02::201:1:1:1:1 -> fd00::201:1:1:1:2 (because first added in the list)
    //   fd01::201:1:1:1:3 -> fd01::201:1:1:1:2 (because in same subnet)
    //   ff02::1           -> fe80::1 (same scope)
    //   2001:db8:3::2     -> 2001:db8:3::1
    //   2001:db9:3::2     -> 2001:db8:3::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR4: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 3);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR4),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_only_link_local() {
    let (mut iface, _, _) = setup(Medium::Ip);

    // List of addresses in the interface:
    //   fe80::1/64
    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    iface.update_ip_addrs(|ips| {
        ips.clear();
        ips.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)))
            .unwrap();
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fe80::1
    //   fd01::201:1:1:1:1 -> fe80::1
    //   fd02::201:1:1:1:1 -> fe80::1
    //   ff02::1           -> fe80::1
    //   2001:db8:3::2     -> fe80::1
    //   2001:db9:3::2     -> fe80::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_empty_interface() {
    let (mut iface, _, _) = setup(Medium::Ip);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> ::1
    //   fd00::201:1:1:1:1 -> ::1
    //   fd01::201:1:1:1:1 -> ::1
    //   fd02::201:1:1:1:1 -> ::1
    //   ff02::1           -> ::1
    //   2001:db8:3::2     -> ::1
    //   2001:db9:3::2     -> ::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_join_ipv6_multicast_group(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let groups = [
        Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb),
        Ipv6Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x0017),
    ];

    let timestamp = Instant::from_millis(0);

    // Drain the unsolicited node multicast report from the device
    iface.poll(timestamp, &mut device, &mut sockets);
    let _ = recv_icmpv6(&mut device, timestamp);

    for &group in &groups {
        iface.join_multicast_group(group).unwrap();
        assert!(iface.has_multicast_group(group));
    }
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));
    iface.poll(timestamp, &mut device, &mut sockets);
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), 2);

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for (&group_addr, ipv6_packet) in groups.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let _ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, 1);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let record = MldAddressRecord::new_checked(record_data).unwrap();
        let record_repr = MldAddressRecordRepr::parse(&record).unwrap();

        assert_eq!(
            record_repr,
            MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: group_addr,
                record_type: MldRecordType::ChangeToInclude,
                aux_data_len: 0,
                payload: &[],
            }
        );

        if !group_addr.is_solicited_node_multicast() {
            iface.leave_multicast_group(group_addr).unwrap();
            assert!(!iface.has_multicast_group(group_addr));
            iface.poll(timestamp, &mut device, &mut sockets);
            assert!(!iface.has_multicast_group(group_addr));
        }
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_handle_valid_multicast_query(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let mut timestamp = Instant::ZERO;

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 100);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let query_ip_addr = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);

    iface.join_multicast_group(query_ip_addr).unwrap();

    iface.poll(timestamp, &mut device, &mut sockets);
    // flush multicast reports from the join_multicast_group calls
    recv_icmpv6(&mut device, timestamp);

    let queries = [
        // General query, expect both multicast addresses back
        (
            Ipv6Address::UNSPECIFIED,
            IPV6_LINK_LOCAL_ALL_NODES,
            vec![local_ip_addr.solicited_node(), query_ip_addr],
        ),
        // Address specific query, expect only the queried address back
        (query_ip_addr, query_ip_addr, vec![query_ip_addr]),
    ];

    for (mcast_query, address, _results) in queries.iter() {
        let query = Icmpv6Repr::Mld(MldRepr::Query {
            max_resp_code: 1000,
            mcast_addr: *mcast_query,
            s_flag: false,
            qrv: 1,
            qqic: 60,
            num_srcs: 0,
            data: &[0, 0, 0, 0],
        });

        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: *address,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 1,
            payload_len: query.buffer_len(),
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        query.emit(
            &remote_ip_addr,
            address,
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
            &ChecksumCapabilities::default(),
        );

        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments,
        );

        timestamp += crate::time::Duration::from_millis(1000);
        iface.poll(timestamp, &mut device, &mut sockets);
    }

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), queries.len());

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for ((_mcast_query, _address, results), ipv6_packet) in queries.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();
        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS);

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, results.len() as u16);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let mut record_reprs = Vec::new();
        let mut payload = record_data;

        // FIXME: parsing multiple address records should be done by the MLD code
        while !payload.is_empty() {
            let record = MldAddressRecord::new_checked(payload).unwrap();
            let mut record_repr = MldAddressRecordRepr::parse(&record).unwrap();
            payload = record_repr.payload;
            record_repr.payload = &[];
            record_reprs.push(record_repr);
        }

        let expected_records = results
            .iter()
            .map(|addr| MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: *addr,
                record_type: MldRecordType::ModeIsExclude,
                aux_data_len: 0,
                payload: &[],
            })
            .collect::<Vec<_>>();

        assert_eq!(record_reprs, expected_records);
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_solicited_node_multicast_autojoin(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    let addr1 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let addr2 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64)).unwrap();
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr2.into(), 64)).unwrap();
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64)).unwrap();
        ip_addrs.push(IpCidr::new(addr2.into(), 64)).unwrap();
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));
}
