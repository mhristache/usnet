use log::{debug, error, warn, info};
use serde::Deserialize;
use std::error::Error;
use ipnetwork::IpNetwork;
use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::collections::HashMap;
use std::thread;
use std::sync::Arc;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::vlan::{Vlan, VlanPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet::datalink::Channel::Ethernet;
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
    arp: PktStats,
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
struct PktStats {
    rx_pkts: u64,
    tx_pkts: u64,
    rx_pkts_accepted: u64,
    rx_pkts_dropped_not_for_us: u64,
    rx_pkts_dropped_malformed: u64,
    rx_pkts_dropped_no_vlan: u64,
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

    let mut stats: Stats = Default::default();

    // Create an ethernet channel to send and receive on
    let (tx, mut rx) = match datalink::channel(&intf, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unsupported channel type: {}"),
        Err(e) => panic!("unable to create channel: {}", e),
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                stats.rx_pkts += 1;
                handle_ethernet_frame(&intf, &EthernetPacket::new(packet).unwrap(), &cfg, &mut stats);
            }
            Err(e) => panic!("unable to receive packets on interface {}: {}", intf.name, e),
        }
        debug!("stats:\n{:#?}", stats);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket, cfg: &CfgIntf, stats: &mut Stats) {
    let interface_name = &interface.name[..];

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            stats.ipv4.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv4_packet(interface_name, ethernet.payload(), ip, stats);
                },
                CfgIntf::Tagged(_) => {
                    stats.ipv4.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Ipv6 => {
            stats.ipv6.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_ipv6_packet(interface_name, ethernet.payload(), ip, stats);
                },
                CfgIntf::Tagged(_) => {
                    stats.ipv6.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Arp => {
            stats.arp.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(ip) => {
                    handle_arp_packet(interface_name, ethernet, ip, stats);
                },
                CfgIntf::Tagged(_) => {
                    stats.arp.rx_pkts_dropped_no_vlan += 1;
                }
            }
        },
        EtherTypes::Vlan => {
            stats.vlan.rx_pkts += 1;
            match cfg {
                CfgIntf::Untagged(_) => {
                    stats.vlan.rx_pkts_dropped_has_vlan += 1;
                },
                CfgIntf::Tagged(vlans) => {
                    handle_vlan_packet(interface_name, ethernet, vlans, stats);
                }
            }
        },
        _ => stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_vlan_packet(interface_name: &str, ethernet: &EthernetPacket, cfg: &CfgVlans, stats: &mut Stats) {
    if let Some(vlan) = VlanPacket::new(ethernet.payload()) {
        let vid = vlan.get_vlan_identifier();
        if cfg.vlans.contains_key(&vid) {
            match vlan.get_ethertype() {
                EtherTypes::Ipv4 => {
                    stats.ipv4.rx_pkts += 1;
                    handle_ipv4_packet(interface_name, vlan.payload(), &cfg.vlans[&vid], stats);
                },
                EtherTypes::Ipv6 => {
                    stats.ipv6.rx_pkts += 1;
                    handle_ipv6_packet(interface_name, vlan.payload(), &cfg.vlans[&vid], stats);
                },
                EtherTypes::Arp => {
                    stats.arp.rx_pkts += 1;
                    handle_arp_packet(interface_name, ethernet, &cfg.vlans[&vid], stats);
                },
                _ => stats.rx_pkts_dropped_unsupported += 1
            }
        } else {
            stats.vlan.rx_pkts_dropped_not_for_us += 1;
        }
    } else {
        stats.vlan.rx_pkts_dropped_malformed += 1;
    }

}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket, cfg: &CfgIp, stats: &mut Stats) {
    if let Some(header) = ArpPacket::new(ethernet.payload()) {
        let dip = header.get_target_proto_addr();
        match cfg.ip {
            IpNetwork::V4(net)if net.ip() == dip => {
                unimplemented!()
            },
            _ => stats.arp.rx_pkts_dropped_not_for_us += 1
        }
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        stats.arp.rx_pkts_dropped_malformed += 1
    }
}

fn handle_ipv4_packet(interface_name: &str, packet: &[u8], cfg: &CfgIp, stats: &mut Stats) {
    if let Some(header) = Ipv4Packet::new(packet) {
        // accept packets to both the linknet ip and the svc ip
        let dip = header.get_destination();
        match (cfg.ip, cfg.svc) {
            (IpNetwork::V4(net), SocketAddr::V4(svc)) if net.ip() == dip || svc.ip() == &dip => {
                unimplemented!()
            },
            _ => stats.ipv4.rx_pkts_dropped_not_for_us += 1
        }
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            stats
        );
    } else {
        stats.ipv4.rx_pkts_dropped_malformed += 1
    }
}

fn handle_ipv6_packet(interface_name: &str, packet: &[u8], cfg: &CfgIp, stats: &mut Stats) {
    if let Some(header) = Ipv6Packet::new(packet) {
        // accept packets to both the linknet ip and the svc ip
        let dip = header.get_destination();
        match (cfg.ip, cfg.svc) {
            (IpNetwork::V6(net), SocketAddr::V6(svc)) if net.ip() == dip || svc.ip() == &dip => {
                unimplemented!()
            },
            _ => stats.ipv6.rx_pkts_dropped_not_for_us += 1
        }
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            stats
        );
    } else {
        stats.ipv6.rx_pkts_dropped_malformed += 1
    }
}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], stats: &mut Stats) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], stats: &mut Stats) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
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
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], stats: &mut Stats) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], stats: &mut Stats) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        stats.rx_pkts_dropped_unsupported += 1
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    stats: &mut Stats
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, stats)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet, stats)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet, stats)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet, stats)
        }
        _ => stats.rx_pkts_dropped_unsupported += 1
    }
}




