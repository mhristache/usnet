#!/bin/sh

INTF="usnetbasicv"
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

docker exec usnet-tt /config/setup-tt.sh

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
  nicolaka/netshoot:latest
