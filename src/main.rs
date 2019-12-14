use ipnetwork::IpNetwork;
use log::{debug, error, info, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkSender;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::*;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{self, echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::vlan::{ClassOfService, MutableVlanPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time;

#[derive(Debug, Deserialize)]
struct Cfg {
    interface: HashMap<String, CfgIntf>,
}

#[derive(Debug, Deserialize)]
struct CfgIntf {
    vlan: HashMap<u16, CfgIp>,
}

#[derive(Debug, Deserialize)]
struct CfgIp {
    ip: IpNetwork,
    gw: IpAddr,
    svc: SocketAddr,
}

#[derive(Debug, Default)]
struct Stats {
    rx_pkts: u32,
    rx_bytes: u64,
    tx_pkts: u32,
    rx_pkts_dropped_unsupported: u32,
    rx_pkts_dropped_malformed: u32,
    rx_pkts_dropped_not_for_us: u32,
    arp: ArpStats,
    ipv4: PktStats,
    ipv6: PktStats,
    udp: UdpStats,
    icmp4: IcmpStats,
}

#[derive(Debug, Default)]
struct PktStats {
    rx_pkts: u32,
    tx_pkts: u32,
    rx_pkts_dropped_not_for_us: u32,
    rx_pkts_dropped_malformed: u32,
}

#[derive(Debug, Default)]
struct ArpStats {
    rx_pkts: u32,
    rx_pkts_request: u32,
    rx_pkts_reply: u32,
    rx_pkts_dropped_malformed: u32,
    rx_pkts_dropped_unsupported: u32,
    rx_pkts_dropped_not_for_us: u32,
    tx_pkts_reply: u32,
    tx_pkts_request: u32,
}

#[derive(Debug, Default)]
struct IcmpStats {
    rx_pkts: u32,
    rx_pkts_request: u32,
    rx_pkts_reply: u32,
    rx_pkts_dropped_malformed: u32,
    rx_pkts_dropped_unsupported: u32,
    tx_pkts_reply: u32,
}

#[derive(Debug, Default)]
struct UdpStats {
    rx_pkts: u32,
    tx_pkts: u32,
    rx_pkts_dropped_not_for_us: u32,
    rx_pkts_dropped_malformed: u32,
}

#[derive(Debug, Default)]
struct SvcStats {
    rx_pkts: u32,
    tx_pkts: u32,
}

struct Chan {
    stats: Stats,
    tx: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
    neighbors: HashMap<(u16, IpAddr), (MacAddr, time::Instant)>,
}

fn main() {
    env_logger::init();
    let cfg: Cfg = match std::env::args().nth(1) {
        Some(p) => {
            debug!("opening file {}", p);
            match std::fs::read_to_string(p) {
                Ok(s) => match serde_yaml::from_str(&s) {
                    Ok(c) => c,
                    Err(e) => panic!("failed to parse the config: {}", e),
                },
                Err(e) => panic!("failed to open the config: {}", e),
            }
        }
        None => {
            writeln!(std::io::stderr(), "{}", "Usage: usnet <config>\n").unwrap();
            std::process::exit(1);
        }
    };
    trace!("config:\n{:#?}", cfg);

    // get all the available network interfaces
    let intfs = datalink::interfaces();
    trace!("available host interfaces:\n{:#?}", intfs);

    let mut channel_threads = Vec::with_capacity(cfg.interface.len());
    for (cfg_intf_name, cfg_intf) in cfg.interface {
        // find the pnet interface for the configured interface name
        let intf = match intfs.iter().find(|i| i.name == cfg_intf_name) {
            Some(i) => i.clone(),
            None => panic!("interface '{}' not found", cfg_intf_name),
        };
        let t = thread::spawn(move || handle_ethernet_channel(intf, cfg_intf));
        channel_threads.push(t);
    }
    for t in channel_threads {
        let _ = t.join();
    }
}

fn handle_ethernet_channel(intf: NetworkInterface, cfg: CfgIntf) {
    info!("opening an ethernet channel on interface '{}'", intf.name);

    let mut ring = af_packet::rx::Ring::from_if_name(&intf.name).unwrap();

    // Create an ethernet channel to send and receive on
    let tx = match datalink::channel(&intf, Default::default()) {
        Ok(Ethernet(tx, _)) => tx,
        Ok(_) => panic!("unsupported channel type: {}"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    // preemptively update the neighbors table for all configured gateways
    let neighbors = HashMap::new();
    let mut chan = Chan {
        tx,
        interface: intf,
        stats: Default::default(),
        neighbors,
    };

    for (vid, ip_cfg) in cfg.vlan.iter() {
        match (ip_cfg.ip.ip(), ip_cfg.gw) {
            (IpAddr::V4(own_ip), IpAddr::V4(gw_ip)) => {
                send_arp_request(own_ip, gw_ip, *vid, &mut chan)
            }
            _ => unimplemented!(),
        }
    }

    // the vlan id is the last 12 bits in vlan_tci
    let vid_mask = (1 << 12) - 1;

    loop {
        let mut block = ring.get_block(); // this will block
        for packet in block.get_raw_packets() {
            chan.stats.rx_pkts += 1;
            chan.stats.rx_bytes += packet.tpacket3_hdr.tp_len as u64;

            // tpacket3_hdr is described here:
            // http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_ring_buffer_in_c.html
            let vid = (packet.tpacket3_hdr.hv1.tp_vlan_tci & vid_mask) as u16;

            match cfg.vlan.get(&vid) {
                Some(ip_cfg) => {
                    let pkt_start = packet.tpacket3_hdr.tp_mac as usize;
                    let pkt_end =
                        packet.tpacket3_hdr.tp_mac as usize + packet.tpacket3_hdr.tp_len as usize;
                    match EthernetPacket::new(&packet.data[pkt_start..pkt_end]) {
                        Some(eth) => handle_ethernet_frame(&eth, &ip_cfg, vid, &mut chan),
                        None => chan.stats.rx_pkts_dropped_malformed += 1,
                    }
                }
                None => {
                    chan.stats.rx_pkts_dropped_not_for_us += 1;
                    continue;
                }
            }
        }
        block.mark_as_consumed();
        trace!("[{}] - stats:\n{:#?}", chan.interface.name, chan.stats);
    }
}

fn send_packet(chan: &mut Chan, packet: &[u8]) {
    if let Err(e) = chan.tx.send_to(packet, None).transpose() {
        error!(
            "[{}]: failed to send packet: {:?}. packet dump: {:?}",
            chan.interface.name, e, &packet
        );
        println!("{:?}", &packet);
    }
    chan.stats.tx_pkts += 1;
}

fn add_neighbor(vlan_id: u16, ip: IpAddr, mac: MacAddr, chan: &mut Chan) {
    chan.neighbors
        .insert((vlan_id, ip), (mac, time::Instant::now()));
    debug!(
        "[{}.{}]: neighbors table updated with {} -> {}",
        chan.interface.name, vlan_id, ip, mac
    );
}

fn get_neighbor(vlan_id: u16, ip: IpAddr, chan: &mut Chan) -> Option<MacAddr> {
    chan.neighbors.get(&(vlan_id, ip)).map(|a| a.0)
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, cfg_ip: &CfgIp, vlan_id: u16, chan: &mut Chan) {
    trace!(
        "[{}.{}]: packet received: {:02x?}",
        &chan.interface.name,
        vlan_id,
        ethernet.packet()
    );
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            chan.stats.ipv4.rx_pkts += 1;
            handle_ipv4_packet(ethernet.payload(), cfg_ip, vlan_id, chan);
        }
        EtherTypes::Ipv6 => {
            chan.stats.ipv6.rx_pkts += 1;
            handle_ipv6_packet(ethernet.payload(), cfg_ip, vlan_id, chan);
        }
        EtherTypes::Arp => {
            chan.stats.arp.rx_pkts += 1;
            handle_arp_packet(ethernet.payload(), cfg_ip, vlan_id, chan);
        }
        _ => chan.stats.rx_pkts_dropped_unsupported += 1,
    }
}

fn send_ethernet_packet(dest_mac: MacAddr, ethertype: EtherType, payload: &[u8], chan: &mut Chan) {
    let buf_size = MutableEthernetPacket::minimum_packet_size() + payload.len();
    let mut ethernet_packet = MutableEthernetPacket::owned(vec![0u8; buf_size]).unwrap();
    ethernet_packet.set_destination(dest_mac);
    ethernet_packet.set_source(chan.interface.mac_address());
    ethernet_packet.set_ethertype(ethertype);
    ethernet_packet.set_payload(payload);
    send_packet(chan, ethernet_packet.packet());
}

fn send_vlan_packet(
    dest_mac: MacAddr,
    ethertype: EtherType,
    vlan_id: u16,
    payload: &[u8],
    chan: &mut Chan,
) {
    let buf_size = MutableVlanPacket::minimum_packet_size() + payload.len();
    let mut vlan_packet = MutableVlanPacket::owned(vec![0u8; buf_size]).unwrap();
    vlan_packet.set_vlan_identifier(vlan_id);
    vlan_packet.set_ethertype(ethertype);
    vlan_packet.set_priority_code_point(ClassOfService::new(0));
    vlan_packet.set_drop_eligible_indicator(0); // should always be 0 for Ethernet
    vlan_packet.set_payload(payload);
    send_ethernet_packet(dest_mac, EtherTypes::Vlan, vlan_packet.packet(), chan);
}

fn handle_arp_packet(payload: &[u8], cfg: &CfgIp, vlan_id: u16, chan: &mut Chan) {
    if let Some(header) = ArpPacket::new(payload) {
        let dip = header.get_target_proto_addr();
        match cfg.ip {
            IpNetwork::V4(net) if net.ip() == dip => match header.get_operation() {
                ArpOperations::Request => {
                    chan.stats.arp.rx_pkts_request += 1;
                    let target_mac = header.get_sender_hw_addr();
                    send_arp_packet(
                        net.ip(),
                        header.get_sender_proto_addr(),
                        target_mac,
                        target_mac,
                        ArpOperations::Reply,
                        vlan_id,
                        chan,
                    );
                    chan.stats.arp.tx_pkts_reply += 1;
                }
                ArpOperations::Reply => {
                    chan.stats.arp.rx_pkts_reply += 1;
                    add_neighbor(
                        vlan_id,
                        IpAddr::V4(header.get_sender_proto_addr()),
                        header.get_sender_hw_addr(),
                        chan,
                    );
                }
                _ => chan.stats.arp.rx_pkts_dropped_unsupported += 1,
            },
            _ => chan.stats.arp.rx_pkts_dropped_not_for_us += 1,
        }
    } else {
        chan.stats.arp.rx_pkts_dropped_malformed += 1
    }
}

fn send_arp_packet(
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    dest_mac: MacAddr,
    operation: ArpOperation,
    vlan_id: u16,
    chan: &mut Chan,
) {
    let buf_size = MutableArpPacket::minimum_packet_size();
    let mut arp_packet = MutableArpPacket::owned(vec![0u8; buf_size]).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(operation);
    arp_packet.set_sender_hw_addr(chan.interface.mac_address());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    if vlan_id == 0 {
        send_ethernet_packet(dest_mac, EtherTypes::Arp, arp_packet.packet(), chan);
    } else {
        send_vlan_packet(
            dest_mac,
            EtherTypes::Arp,
            vlan_id,
            arp_packet.packet(),
            chan,
        );
    };
}

fn send_arp_request(source_ip: Ipv4Addr, target_ip: Ipv4Addr, vlan_id: u16, chan: &mut Chan) {
    send_arp_packet(
        source_ip,
        target_ip,
        MacAddr::zero(),
        MacAddr::broadcast(),
        ArpOperations::Request,
        vlan_id,
        chan,
    );
    chan.stats.arp.tx_pkts_request += 1;
}

fn handle_ipv4_packet(packet: &[u8], cfg: &CfgIp, vlan_id: u16, chan: &mut Chan) {
    if let Some(header) = Ipv4Packet::new(packet) {
        // accept packets to both the linknet ip and the svc ip
        let dip = header.get_destination();
        match (cfg.ip, cfg.svc) {
            (IpNetwork::V4(net), SocketAddr::V4(svc)) if net.ip() == dip || svc.ip() == &dip => {
                handle_transport_protocol(
                    IpAddr::V4(header.get_source()),
                    IpAddr::V4(header.get_destination()),
                    header.get_next_level_protocol(),
                    header.payload(),
                    &cfg.svc,
                    vlan_id,
                    chan,
                );
            }
            _ => chan.stats.ipv4.rx_pkts_dropped_not_for_us += 1,
        }
    } else {
        chan.stats.ipv4.rx_pkts_dropped_malformed += 1
    }
}

fn send_ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
    vlan_id: u16,
    chan: &mut Chan,
) {
    let buf_size = MutableIpv4Packet::minimum_packet_size() + payload.len();
    let mut ip_packet = MutableIpv4Packet::owned(vec![0u8; buf_size]).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(5); // 5 × 32 bits = 160 bits = 20 bytes
    ip_packet.set_dscp(0); // DF - Default Forwarding
    ip_packet.set_ecn(0);
    ip_packet.set_total_length(buf_size as u16);
    ip_packet.set_identification(0);
    ip_packet.set_flags(2); // 010 - DF bit set
    ip_packet.set_fragment_offset(0);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(protocol);
    ip_packet.set_source(source);
    ip_packet.set_destination(destination);
    ip_packet.set_payload(payload);
    let checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    // TODO: implement some buffering and retry if arp resolving failed
    let dest_mac = get_neighbor(vlan_id, IpAddr::V4(destination), chan).unwrap();

    if vlan_id == 0 {
        send_ethernet_packet(dest_mac, EtherTypes::Ipv4, ip_packet.packet(), chan);
    } else {
        send_vlan_packet(
            dest_mac,
            EtherTypes::Ipv4,
            vlan_id,
            ip_packet.packet(),
            chan,
        );
    };
}

fn handle_ipv6_packet(packet: &[u8], cfg: &CfgIp, vlan_id: u16, chan: &mut Chan) {
    if let Some(header) = Ipv6Packet::new(packet) {
        // accept packets to both the linknet ip and the svc ip
        let dip = header.get_destination();
        match (cfg.ip, cfg.svc) {
            (IpNetwork::V6(net), SocketAddr::V6(svc)) if net.ip() == dip || svc.ip() == &dip => {
                handle_transport_protocol(
                    IpAddr::V6(header.get_source()),
                    IpAddr::V6(header.get_destination()),
                    header.get_next_header(),
                    header.payload(),
                    &cfg.svc,
                    vlan_id,
                    chan,
                );
            }
            _ => chan.stats.ipv6.rx_pkts_dropped_not_for_us += 1,
        }
    } else {
        chan.stats.ipv6.rx_pkts_dropped_malformed += 1
    }
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    svc: &SocketAddr,
    vlan_id: u16,
    chan: &mut Chan,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(source, destination, packet, svc, vlan_id, chan)
        }
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(source, destination, packet, chan),
        IpNextHeaderProtocols::Icmp => match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                handle_icmp_packet(source, destination, packet, vlan_id, chan)
            }
            _ => chan.stats.rx_pkts_dropped_malformed += 1,
        },
        IpNextHeaderProtocols::Icmpv6 => match (source, destination) {
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                handle_icmpv6_packet(source, destination, packet, chan)
            }
            _ => chan.stats.rx_pkts_dropped_malformed += 1,
        },
        _ => chan.stats.rx_pkts_dropped_unsupported += 1,
    }
}

fn handle_udp_packet(
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    svc: &SocketAddr,
    vlan_id: u16,
    chan: &mut Chan,
) {
    chan.stats.udp.rx_pkts += 1;
    if let Some(udp) = UdpPacket::new(packet) {
        if udp.get_destination() == svc.port() {
            chan.stats.udp.rx_pkts += 1;
            debug!(
                "[{}.{}]: UDP Packet received: {}:{} > {}:{}; length: {}",
                chan.interface.name,
                vlan_id,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            );
            // reply
            let reply_str = format!("Hello from {}", svc.ip());
            let buf_size = MutableUdpPacket::minimum_packet_size() + reply_str.len();
            let mut udp_packet = MutableUdpPacket::owned(vec![0u8; buf_size]).unwrap();
            udp_packet.set_source(udp.get_destination());
            udp_packet.set_destination(udp.get_source());
            udp_packet.set_length(buf_size as u16);
            udp_packet.set_payload(reply_str.as_bytes());
            // TODO: add checksum
            match (source, destination) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    send_ipv4_packet(
                        d,
                        s,
                        IpNextHeaderProtocols::Udp,
                        udp_packet.packet_mut(),
                        vlan_id,
                        chan,
                    );
                    debug!(
                        "[{}.{}]: UDP Packet sent: {}:{} > {}:{}; length: {}",
                        chan.interface.name,
                        vlan_id,
                        d,
                        udp_packet.get_source(),
                        s,
                        udp_packet.get_destination(),
                        udp_packet.get_length()
                    );
                    chan.stats.udp.tx_pkts += 1;
                }
                _ => unimplemented!(),
            }
        } else {
            chan.stats.udp.rx_pkts_dropped_not_for_us += 1;
        }
    } else {
        chan.stats.udp.rx_pkts_dropped_malformed += 1
    }
}

fn handle_icmp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    packet: &[u8],
    vlan_id: u16,
    chan: &mut Chan,
) {
    chan.stats.icmp4.rx_pkts += 1;
    if let Some(icmp_packet) = IcmpPacket::new(packet) {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                chan.stats.icmp4.rx_pkts_reply += 1;
            }
            IcmpTypes::EchoRequest => {
                chan.stats.icmp4.rx_pkts_request += 1;
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                debug!(
                    "[{}.{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    chan.interface.name,
                    vlan_id,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier(),
                );

                // build a reply packet using the request as base
                let mut echo_reply_packet =
                    echo_reply::MutableEchoReplyPacket::owned(packet.to_vec()).unwrap();
                echo_reply_packet.set_icmp_type(IcmpTypes::EchoReply);
                let icmp_packet = IcmpPacket::new(echo_reply_packet.packet()).unwrap();
                let checksum = icmp::checksum(&icmp_packet);
                echo_reply_packet.set_checksum(checksum);
                send_ipv4_packet(
                    destination,
                    source,
                    IpNextHeaderProtocols::Icmp,
                    echo_reply_packet.packet(),
                    vlan_id,
                    chan,
                );
                debug!(
                    "[{}.{}]: ICMP echo reply   {} -> {} (seq={:?}, id={:?})",
                    chan.interface.name,
                    vlan_id,
                    destination,
                    source,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier(),
                );
                chan.stats.icmp4.tx_pkts_reply += 1;
            }
            _ => debug!(
                "[{}.{}]: ICMP packet received {} -> {} (type={:?})",
                chan.interface.name,
                vlan_id,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        chan.stats.icmp4.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_icmpv6_packet(source: Ipv6Addr, destination: Ipv6Addr, packet: &[u8], chan: &mut Chan) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        debug!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            chan.interface.name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        chan.stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], chan: &mut Chan) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        debug!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            chan.interface.name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        chan.stats.rx_pkts_dropped_unsupported += 1
    }
}
