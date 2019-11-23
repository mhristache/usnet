#!/bin/sh

ip link add usnetadv type dummy
ip link set usnetadv up

ip link add link usnetadv usnetadvr type macvlan mode bridge
ip link set usnetadvr up
ip addr add 10.30.1.1/29 dev usnetadvr

ip link add link usnetadv usnetadvl1 type macvlan mode bridge
ip link set usnetadvl1 up

ip link add link usnetadv usnetadvl2 type macvlan mode bridge
ip link set usnetadvl2 up

ip link add link usnetadvr usnetadvr.10 type vlan id 10
ip link set usnetadvr.10 up
ip addr add 10.10.1.1/29 dev usnetadvr.10

ip link add link usnetadvr usnetadvr.20 type vlan id 20
ip link set usnetadvr.20 up
ip addr add 10.20.1.1/29 dev usnetadvr.20

