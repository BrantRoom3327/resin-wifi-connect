#!/bin/bash
set -e

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

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

if [ "${PRODUCTION}" == "1" ]; then
    scripts/local-build.sh x86_64-unknown-linux-gnu 
elif [ "${USE_HOTSPOT}" == "1" ]; then 
    cargo build
    target/debug/wifi-connect --portal-interface=wlp2s0 --portal-ssid=QMTest
else
    #this is the default with no options.  It only runs the http server and tries to operate without a hotspot but allow for 
    #setting system params.  
    cargo build --features="no_hotspot"
    cp target/debug/wifi-connect .
    #to find /sbin/ifconfig on the pi by default.
    export PATH="$PATH:/sbin/" 
    ./wifi-connect --portal-gateway=192.168.1.148 --config-file=./data/cfg.json --auth-file=./data/auth.json
fi
