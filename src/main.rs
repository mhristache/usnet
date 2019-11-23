use ipnetwork::IpNetwork;
use log::{debug, error, info};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkSender;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::*;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::{ClassOfService, MutableVlanPacket, VlanPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time;

#[derive(Debug, Deserialize)]
struct Config {
    interfaces: HashMap<String, CfgIntf>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CfgIntf {
    Untagged(CfgIp),
    Tagged(CfgVlans),
}

#[derive(Debug, Deserialize)]
struct CfgVlans {
    vlans: HashMap<u16, CfgIp>,
}

#[derive(Debug, Deserialize)]
struct CfgIp {
    ip: IpNetwork,
    gw: IpAddr,
    svc: SocketAddr,
}

#[derive(Debug, Default)]
struct Stats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_dropped_unsupported: u64,
    ipv4: PktStats,
    ipv6: PktStats,
    arp: ArpStats,
    vlan: VlanStats,
}

#[derive(Debug, Default)]
struct PktStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_accepted: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_no_vlan: u64,
}

#[derive(Debug, Default)]
struct VlanStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_accepted: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_has_vlan: u64,
    rx_pkts_dropped_malformed: u64,
}

#[derive(Debug, Default)]
struct ArpStats {
    rx_pkts: u64,
    rx_pkts_request: u64,
    rx_pkts_reply: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_has_vlan: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_no_vlan: u64,
    rx_pkts_dropped_unsupported: u64,
    tx_pkts_reply: u64,
    tx_pkts_request: u64,
}

#[derive(Debug, Default)]
struct UdpStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_unsupported: u64,
}

#[derive(Debug, Default)]
struct IcmpStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_request: u64,
    rx_pkts_reply: u64,
    tx_pkts_reply: u64,
    tx_pkts_request: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_unsupported: u64,
}

struct Chan {
    stats: Stats,
    tx: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
    neighbors: HashMap<(Option<u16>, IpAddr), (MacAddr, time::Instant)>,
}

fn main() {
    env_logger::init();
    let cfg: Config = match std::env::args().nth(1) {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => match serde_yaml::from_str(&s) {
                Ok(c) => c,
                Err(e) => panic!("failed to parse the config: {}", e),
            },
            Err(e) => panic!("failed to open the config: {}", e),
        },
        None => {
            writeln!(
                std::io::stderr(),
                "{}",
                "Usage: raw-sockets-playground <config>\n"
            )
            .unwrap();
            std::process::exit(1);
        }
    };
    debug!("config:\n{:#?}", cfg);

    // get all the available network interfaces
    let intfs = datalink::interfaces();
    debug!("interfaces:\n{:#?}", intfs);

    let mut channel_threads = Vec::with_capacity(cfg.interfaces.len());
    for (cfg_intf_name, cfg_intf) in cfg.interfaces {
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

    // Create an ethernet channel to send and receive on
    let (tx, mut rx) = match datalink::channel(&intf, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unsupported channel type: {}"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    // TODO: redesign this logic to retrieve the neighbors in an on demand manner
    // preemptively update the neighbors table for all configured gateways
    let neighbors = HashMap::new();
    let mut chan = Chan {
        tx,
        interface: intf,
        stats: Default::default(),
        neighbors,
    };

    match cfg {
        CfgIntf::Untagged(ref c) => match (c.ip.ip(), c.gw) {
            (IpAddr::V4(own_ip), IpAddr::V4(gw_ip)) => {
                send_arp_request(own_ip, gw_ip, None, &mut chan)
            }
            _ => unimplemented!(),
        },
        CfgIntf::Tagged(ref c) => {
            for (vid, ip_cfg) in c.vlans.iter() {
                match (ip_cfg.ip.ip(), ip_cfg.gw) {
                    (IpAddr::V4(own_ip), IpAddr::V4(gw_ip)) => {
                        send_arp_request(own_ip, gw_ip, Some(*vid), &mut chan)
                    }
                    _ => unimplemented!(),
                }
            }
        }
    }

    loop {
        match rx.next() {
            Ok(packet) => {
                chan.stats.rx_pkts += 1;
                handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &cfg, &mut chan);
            }
            Err(e) => panic!(
                "unable to receive packets on interface {}: {}",
                chan.interface.name, e
            ),
        }
        debug!("<{}> stats:\n{:#?}", chan.interface.name, chan.stats);
    }
}

fn send_packet(chan: &mut Chan, packet: &[u8]) {
    if let Err(e) = chan.tx.send_to(packet, None).transpose() {
        error!("<{}> failed to send packet: {:?}. packet dump: {:?}", chan.interface.name, e, &packet);
        println!("{:?}", &packet);
    }
    chan.stats.tx_pkts += 1;
}

fn add_neighbor(vlan_id: Option<u16>, ip: IpAddr, mac: MacAddr, chan: &mut Chan) {
    chan.neighbors
        .insert((vlan_id, ip), (mac, time::Instant::now()));
    debug!(
        "<{} - {:?}> neighbors table updated with {} -> {}",
        chan.interface.name, vlan_id, ip, mac
    );
}

fn get_neighbor(vlan_id: Option<u16>, ip: IpAddr, chan: &mut Chan) -> Option<MacAddr> {
    chan.neighbors.get(&(vlan_id, ip)).map(|a| a.0)
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, cfg: &CfgIntf, chan: &mut Chan) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            chan.stats.ipv4.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv4_packet(ethernet.payload(), ip, chan);
                }
                CfgIntf::Tagged(_) => {
                    chan.stats.ipv4.rx_pkts_dropped_no_vlan += 1;
                }
            }
        }
        EtherTypes::Ipv6 => {
            chan.stats.ipv6.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv6_packet(ethernet.payload(), ip, chan);
                }
                CfgIntf::Tagged(_) => {
                    chan.stats.ipv6.rx_pkts_dropped_no_vlan += 1;
                }
            }
        }
        EtherTypes::Arp => {
            chan.stats.arp.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_arp_packet(ethernet.payload(), None, ip, chan);
                }
                CfgIntf::Tagged(_) => {
                    chan.stats.arp.rx_pkts_dropped_no_vlan += 1;
                }
            }
        }
        EtherTypes::Vlan => {
            chan.stats.vlan.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(_) => {
                    chan.stats.vlan.rx_pkts_dropped_has_vlan += 1;
                }
                CfgIntf::Tagged(vlans) => {
                    handle_vlan_packet(ethernet, vlans, chan);
                }
            }
        }
        _ => chan.stats.rx_pkts_dropped_unsupported += 1,
    }
}

fn handle_vlan_packet(ethernet: &EthernetPacket, cfg: &CfgVlans, chan: &mut Chan) {
    if let Some(vlan) = VlanPacket::new(ethernet.payload()) {
        let vid = vlan.get_vlan_identifier();
        if cfg.vlans.contains_key(&vid) {
            match vlan.get_ethertype() {
                EtherTypes::Ipv4 => {
                    chan.stats.ipv4.rx_pkts += 1;
                    handle_ipv4_packet(vlan.payload(), &cfg.vlans[&vid], chan);
                }
                EtherTypes::Ipv6 => {
                    chan.stats.ipv6.rx_pkts += 1;
                    handle_ipv6_packet(vlan.payload(), &cfg.vlans[&vid], chan);
                }
                EtherTypes::Arp => {
                    chan.stats.arp.rx_pkts += 1;
                    handle_arp_packet(ethernet.payload(), Some(vid), &cfg.vlans[&vid], chan);
                }
                _ => chan.stats.rx_pkts_dropped_unsupported += 1,
            }
        } else {
            chan.stats.vlan.rx_pkts_dropped_not_for_us += 1;
        }
    } else {
        chan.stats.vlan.rx_pkts_dropped_malformed += 1;
    }
}

fn handle_arp_packet(payload: &[u8], vlan_id: Option<u16>, cfg: &CfgIp, chan: &mut Chan) {
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
    vlan_id: Option<u16>,
    chan: &mut Chan,
) {
    let mut arp_buffer = [0u8; MutableArpPacket::minimum_packet_size()];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(operation);
    arp_packet.set_sender_hw_addr(chan.interface.mac_address());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    if let Some(vid) = vlan_id {
        let mut vlan_buffer = [0u8; MutableVlanPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size()];
        let mut vlan_packet = MutableVlanPacket::new(&mut vlan_buffer).unwrap();
        vlan_packet.set_vlan_identifier(vid);
        vlan_packet.set_ethertype(EtherTypes::Arp);
        vlan_packet.set_priority_code_point(ClassOfService::new(7)); // NC - network control
        vlan_packet.set_drop_eligible_indicator(0); // should always be 0 for Ethernet
        vlan_packet.set_payload(arp_packet.packet_mut());

        // the ethernet packet is at least 64 bytes
        const BUF_SIZE: usize = MutableEthernetPacket::minimum_packet_size() + MutableVlanPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();
        let mut ethernet_buffer = [0u8; BUF_SIZE];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_source(chan.interface.mac_address());
        ethernet_packet.set_ethertype(EtherTypes::Vlan);
        ethernet_packet.set_payload(vlan_packet.packet_mut());
        send_packet(chan, ethernet_packet.packet());
    } else {
        // the ethernet packet is at least 64 bytes
        const BUF_SIZE: usize = MutableEthernetPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();
        let mut ethernet_buffer = [0u8; BUF_SIZE];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_source(chan.interface.mac_address());
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        ethernet_packet.set_payload(arp_packet.packet_mut());
        send_packet(chan, ethernet_packet.packet());
    };
}

fn send_arp_request(
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    vlan_id: Option<u16>,
    chan: &mut Chan,
) {
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

fn handle_ipv4_packet(packet: &[u8], cfg: &CfgIp, chan: &mut Chan) {
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
    vlan_id: Option<u16>,
    chan: &mut Chan,
) {
    let mut ip_buffer = [0u8; MutableIpv4Packet::minimum_packet_size()];
    let ip_buffer_len = ip_buffer.len();
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(ip_buffer_len as u8);
    ip_packet.set_dscp(0); // DF - Default Forwarding
    ip_packet.set_ecn(0);
    ip_packet.set_total_length(ip_buffer_len as u16 + payload.len() as u16);
    ip_packet.set_identification(0);
    ip_packet.set_flags(2); // 010 - DF bit set
    ip_packet.set_fragment_offset(0);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(protocol);
    ip_packet.set_source(source);
    ip_packet.set_destination(destination);
    ip_packet.set_payload(payload);
    ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

    let mut ethernet_buffer = [0u8; MutableEthernetPacket::minimum_packet_size()];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    // TODO: improve arp handling
    let dest_mac_address = get_neighbor(vlan_id, IpAddr::V4(destination), chan).unwrap();
    ethernet_packet.set_destination(dest_mac_address);
    ethernet_packet.set_source(chan.interface.mac_address());

    if let Some(vid) = vlan_id {
        let mut vlan_buffer = [0u8; MutableVlanPacket::minimum_packet_size()];
        let mut vlan_packet = MutableVlanPacket::new(&mut vlan_buffer).unwrap();
        ethernet_packet.set_ethertype(EtherTypes::Vlan);
        vlan_packet.set_vlan_identifier(vid);
        vlan_packet.set_ethertype(EtherTypes::Ipv4);
        vlan_packet.set_priority_code_point(ClassOfService::new(7)); // NC - network control
        vlan_packet.set_drop_eligible_indicator(0); // should always be 0 for Ethernet
        vlan_packet.set_payload(ip_packet.packet_mut());
        ethernet_packet.set_payload(vlan_packet.packet_mut());
    } else {
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        ethernet_packet.set_payload(ip_packet.packet_mut());
    };
    send_packet(chan, ethernet_packet.packet());
}

fn handle_ipv6_packet(packet: &[u8], cfg: &CfgIp, chan: &mut Chan) {
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
    chan: &mut Chan,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => handle_udp_packet(source, destination, packet, chan),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(source, destination, packet, chan),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(source, destination, packet, chan),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(source, destination, packet, chan),
        _ => chan.stats.rx_pkts_dropped_unsupported += 1,
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], chan: &mut Chan) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            chan.interface.name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        chan.stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], chan: &mut Chan) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    chan.interface.name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    chan.interface.name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                chan.interface.name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        chan.stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8], chan: &mut Chan) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
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
        println!(
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
