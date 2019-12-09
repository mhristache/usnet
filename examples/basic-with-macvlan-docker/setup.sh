#!/bin/bash

INTF="usnetbasic"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

${DIR}/cleanup.sh > /dev/null 2>&1

ip link add ${INTF} type dummy
ip link set ${INTF} up

docker network create -d macvlan -o parent=${INTF} ${INTF}

docker run \
  -it \
  --name=usnet-tt \
  --net=${INTF} \
  --rm \
  --detach \
  --privileged=true \
  -v $DIR:/config \
  nicolaka/netshoot:latest

docker exec usnet-tt ip addr flush eth0
docker exec usnet-tt ip addr add 10.0.10.1/29 dev eth0
docker exec usnet-tt ip route add default via 10.0.10.2

docker run \
  -it \
  --name=usnet-app \
  --net=${INTF} \
  -v $DIR/../../target/x86_64-unknown-linux-musl/:/app \
  -v $DIR:/config \
  --rm \
  --detach \
  --privileged=true \
  -e RUST_LOG=trace -e RUST_BACKTRACE=1 \
  --entrypoint "/app/debug/usnet" \
  nicolaka/netshoot:latest \
  /config/config.yaml

docker exec usnet-app ip addr flush eth0

docker exec usnet-tt ping -c 3 10.0.10.2
docker exec usnet-tt ping -c 3 10.0.100.1