#!/bin/sh

ip link add dummy1 type dummy
ip link set dummy1 up
ip addr add 10.11.12.3/29 dev dummy1

ip link add dummy2 type dummy
ip link set dummy2 up
