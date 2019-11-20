use log::{debug, error, warn, info};
use serde::Deserialize;
use std::error::Error;
use ipnetwork::IpNetwork;
use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use std::collections::HashMap;
use std::thread;
use std::sync::Arc;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::*;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::vlan::{Vlan, VlanPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkSender;
use std::alloc::dealloc;


#[derive(Debug, Deserialize)]
struct Config {
    interfaces: HashMap<String, CfgIntf>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CfgIntf {
    Untagged(CfgIp),
    Tagged(CfgVlans)
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
    rx_pkts_dropped_unsupported: u64,
    ipv4: PktStats,
    ipv6: PktStats,
    arp: ArpStats,
    vlan: VlanStats,
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
struct PktStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_accepted: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_no_vlan: u64,
}

struct Chan {
    stats: Stats,
    tx: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
}

fn main() {
    env_logger::init();
    let cfg: Config = match std::env::args().nth(1) {
        Some(p) => {
            match std::fs::read_to_string(p) {
                Ok(s) => match serde_yaml::from_str(&s) {
                    Ok(c) => c,
                    Err(e) => panic!("failed to parse the config: {}", e)
                },
                Err(e) => panic!("failed to open the config: {}", e)
            }
        },
        None => {
            writeln!(std::io::stderr(), "{}", "Usage: raw-sockets-playground <config>\n").unwrap();
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
            None => panic!("interface '{}' not found", cfg_intf_name)
        };
        let t = thread::spawn(move || {
            handle_ethernet_channel(intf, cfg_intf)
        });
        channel_threads.push(t);
    }
    for t in channel_threads {
        let _ = t.join();
    }
}

fn handle_ethernet_channel(intf: NetworkInterface, cfg: CfgIntf) {
    debug!("opening an ethernet channel on interface '{}'", intf.name);

    // Create an ethernet channel to send and receive on
    let (tx, mut rx) = match datalink::channel(&intf, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unsupported channel type: {}"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    let mut chan = Chan { tx, interface: intf, stats: Default::default()};

    loop {
        match rx.next() {
            Ok(packet) => {
                chan.stats.rx_pkts += 1;
                handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &cfg, &mut chan);
            }
            Err(e) => panic!("unable to receive packets on interface {}: {}", chan.interface.name, e),
        }
        debug!("stats:\n{:#?}", chan.stats);
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, cfg: &CfgIntf, chan: &mut Chan) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            chan.stats.ipv4.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv4_packet(ethernet.payload(), ip, chan);
                },
                CfgIntf::Tagged(_) => {
                    chan.stats.ipv4.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Ipv6 => {
            chan.stats.ipv6.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv6_packet(ethernet.payload(), ip, chan);
                },
                CfgIntf::Tagged(_) => {
                    chan.stats.ipv6.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Arp => {
            chan.stats.arp.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_arp_packet(ethernet, ip, chan);
                },
                CfgIntf::Tagged(_) => {
                    chan.stats.arp.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Vlan => {
            chan.stats.vlan.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(_) => {
                    chan.stats.vlan.rx_pkts_dropped_has_vlan += 1;
                },
                CfgIntf::Tagged(vlans) => {
                    handle_vlan_packet(ethernet, vlans, chan);
                }
            }
        },
        _ => chan.stats.rx_pkts_dropped_unsupported += 1
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
                },
                EtherTypes::Ipv6 => {
                    chan.stats.ipv6.rx_pkts += 1;
                    handle_ipv6_packet(vlan.payload(), &cfg.vlans[&vid], chan);
                },
                EtherTypes::Arp => {
                    chan.stats.arp.rx_pkts += 1;
                    handle_arp_packet(ethernet, &cfg.vlans[&vid], chan);
                },
                _ => chan.stats.rx_pkts_dropped_unsupported += 1
            }
        } else {
            chan.stats.vlan.rx_pkts_dropped_not_for_us += 1;
        }
    } else {
        chan.stats.vlan.rx_pkts_dropped_malformed += 1;
    }

}

fn handle_arp_packet(ethernet: &EthernetPacket, cfg: &CfgIp, chan: &mut Chan) {
    if let Some(header) = ArpPacket::new(ethernet.payload()) {
        let dip = header.get_target_proto_addr();
        match cfg.ip {
            IpNetwork::V4(net)if net.ip() == dip => {
                match header.get_operation() {
                    ArpOperations::Request => {
                        chan.stats.arp.rx_pkts_request += 1;
                        send_arp_reply(&header, dip, chan);
                        chan.stats.arp.tx_pkts_reply += 1;
                    },
                    ArpOperations::Reply => {
                        chan.stats.arp.rx_pkts_reply += 1;
                    },
                    _ => chan.stats.arp.rx_pkts_dropped_unsupported += 1,
                }
            },
            _ => chan.stats.arp.rx_pkts_dropped_not_for_us += 1
        }
    } else {
        chan.stats.arp.rx_pkts_dropped_malformed += 1
    }
}

// send the reply to an arp request
fn send_arp_reply(arp_req: &ArpPacket, source_ip: Ipv4Addr, chan: &mut Chan) {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(arp_req. get_sender_hw_addr());
    ethernet_packet.set_source(chan.interface.mac_address());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(chan.interface.mac_address());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(arp_req.get_sender_hw_addr());
    arp_packet.set_target_proto_addr(arp_req.get_sender_proto_addr());

    ethernet_packet.set_payload(arp_packet.packet_mut());

    chan.tx.send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();
}

fn send_arp_request(source_ip: Ipv4Addr, target_ip: Ipv4Addr, chan: &mut Chan) {

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(chan.interface.mac_address());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(chan.interface.mac_address());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    chan.tx.send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();
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
                    chan
                );
            },
            _ => chan.stats.ipv4.rx_pkts_dropped_not_for_us += 1
        }
    } else {
        chan.stats.ipv4.rx_pkts_dropped_malformed += 1
    }
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
                    chan
                );
            },
            _ => chan.stats.ipv6.rx_pkts_dropped_not_for_us += 1
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
    chan: &mut Chan
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(source, destination, packet, chan)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(source, destination, packet, chan)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(source, destination, packet, chan)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(source, destination, packet, chan)
        }
        _ => chan.stats.rx_pkts_dropped_unsupported += 1
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





