#!/bin/sh

ip link add link eth0 vlan10 type vlan id 10
ip link set vlan10 up
ip addr add 10.1.1.1/29 dev vlan10
ip route add 10.1.100.1 via 10.1.1.2