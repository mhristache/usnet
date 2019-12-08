#!/bin/sh

ip link add usnetbasic type dummy
ip link set usnetbasic up

ip link add link usnetbasic usnetbasicr type macvlan mode bridge
ip link set usnetbasicr up
ip addr add 10.0.10.1/29 dev usnetbasicr

ip link add link usnetbasic usnetbasicl type macvlan mode bridge
ip link set usnetbasicl up

ip route add 10.0.100.1 via 10.0.10.2