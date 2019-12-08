#!/bin/sh

INTF="usnetbasicv"

ip link add ${INTF} type dummy
ip link set ${INTF} up

ip link add link ${INTF} ${INTF}r type macvlan mode bridge
ip link set ${INTF}r up

ip link add link ${INTF} ${INTF}l type macvlan mode bridge
ip link set ${INTF}l up

ip link add link ${INTF}r ${INTF}r.10 type vlan id 10
ip link set ${INTF}r.10 up
ip addr add 10.1.1.1/29 dev ${INTF}r.10

ip route add 10.1.100.1 via 10.1.1.2
