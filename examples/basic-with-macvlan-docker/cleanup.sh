#!/bin/bash

INTF="usnetbasic"

docker kill usnet-app
docker kill usnet-tt
docker network rm ${INTF}
ip link del ${INTF}
