#!/bin/bash
set -e

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

#default for the script is to build for debug, no hotspot and no docker
#local is a local build using docker with the hotspot
#production is a release for arm on the RPI3

case $key in
    -l|--local)
    LOCAL_DOCKER=1
    shift # past arg 
    ;;
    -h|--hotspot)
    USE_HOTSPOT=1
    shift # past arg 
    ;;
    #build for arm v7, push to resin and run f
    -p|--production)
    PRODUCTION=1
    shift # past arg 
    ;;
esac
done

#echo PRODUCTION = "${PRODUCTION}"
#echo LOCAL_DOCKER = "${LOCAL_DOCKER}"
#echo USE_HOTSPOT = "${USE_HOTSPOT}"

if [ "${PRODUCTION}" == "1" ]; then
    #build the release for docker push.  
    #NOTE: We are building for the raspberry pi or armv7 chips here.
    scripts/local-build.sh armv7-unknown-linux-gnueabihf
    docker build --rm -t wifitest .
elif [ "${LOCAL_DOCKER}" == "1" ]; then 
    # use the local Dockerfile to build an image, and leave hotspot enabled.
    cargo build
    cp target/debug/wifi-connect .
    docker build --rm -t wifitest .
elif [ "${USE_HOTSPOT}" == "1" ]; then 
    cargo build
    cp target/debug/wifi-connect .
    ./wifi-connect --portal-interface=wlp2s0 --collector-wifi=wlp2s0 --collector-ethernet=eth0
else
    #this is the default with no options.  It only runs the http server and tries to operate without a hotspot but allow for 
    #setting system params.  You will likely need to sudo the wifi-connect command below to actually set system params (ethernet settings).
    cargo build --features="no_hotspot"
    cp target/debug/wifi-connect .
    ./wifi-connect --portal-gateway=192.168.1.148 --collector-ethernet=en0 --collector-wifi=wlan0
fi
