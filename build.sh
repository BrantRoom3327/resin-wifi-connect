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
    #build for arm v7, push to resin and run f
    -p|--production)
    PRODUCTION=1
    shift # past arg 
    ;;
esac
done

#echo PRODUCTION = "${PRODUCTION}"
#echo LOCAL_DOCKER = "${LOCAL_DOCKER}"

if [ "${PRODUCTION}" == "1" ]; then
    #build the release for docker push.  
    #NOTE: We are building for the raspberry pi or armv7 chips here.
    scripts/local-build.sh armv7-unknown-linux-gnueabihf
    docker build --rm -t wifitest .
elif [ "${LOCAL_DOCKER}" == "1" ]; then 
    # use the local Dockerfile to build an image
    scripts/local-build.sh x86_64-unknown-linux-gnu
    docker build --rm -t wifitest .
else
    #run a debug build, default
    cargo build --features="localbuild"
    cp target/debug/wifi-connect .
    ./wifi-connect --portal-interface=en0
    # if you need to set by ip address instead.
    #./wifi-connect --portal-gateway=192.168.1.148
fi