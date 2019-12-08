#!/bin/sh

INTF="usnetbasicv"

docker kill usnet-app
docker kill usnet-tt
docker network rm ${INTF}
ip link del ${INTF}
