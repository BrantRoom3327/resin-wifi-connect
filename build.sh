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
    #build the release for docker push on the Intel NUC
    scripts/local-build.sh x86_64-unknown-linux-gnu 
    #package up the files and put them in releases, '-p' is for production
    #./package-files.sh -p
elif [ "${USE_HOTSPOT}" == "1" ]; then 
    cargo build
    cp target/debug/wifi-connect .
    ./wifi-connect --portal-interface=wlp2s0 --collector-wifi=wlp2s0 --collector-ethernet=eth0
else
    #this is the default with no options.  It only runs the http server and tries to operate without a hotspot but allow for 
    #setting system params.  
    cargo build --features="no_hotspot"
    cp target/debug/wifi-connect .
    #to find /sbin/ifconfig on the pi by default.
    export PATH="$PATH:/sbin/" 
    ./wifi-connect --portal-gateway=192.168.1.148 --config-file=./data/cfg.json --auth-file=./data/auth.json
fi
