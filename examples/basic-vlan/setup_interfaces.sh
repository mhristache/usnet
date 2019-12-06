#!/bin/sh

ip link add usnetbasicv type dummy
ip link set usnetbasicv up

ip link add link usnetbasicv usnetbasicvr type macvlan mode bridge
ip link set usnetbasicvr up

ip link add link usnetbasicv usnetbasicvl type macvlan mode bridge
ip link set usnetbasicvl up

ip link add link usnetbasicvr usnetbasicvr.10 type vlan id 10
ip link set usnetbasicvr.10 up
ip addr add 10.1.1.1/29 dev usnetbasicvr.10

ip route add 10.1.100.1 via 10.0.10.2