#!/bin/bash
set -e

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -pi|--pi|-p)
    RASPBERRY_PI=1
    shift # past arg 
    ;;
    -intel|--intel|-i)
    INTEL_NUC=1
    shift # past arg 
    ;;
esac
done

if [ "${RASPBERRY_PI}" == "1" ]; then
    scripts/local-build.sh armv7-unknown-linux-gnueabihf armv7hf
    cp Dockerfile.template.rpi Dockerfile.template
elif [ "${INTEL_NUC}" == "1" ]; then
    scripts/local-build.sh x86_64-unknown-linux-gnu amd64 
    cp Dockerfile.template.intel Dockerfile.template
else
    #this is the default with no options.  It only runs the http server and tries to operate without a hotspot but allow for 
    #setting system params.  
    cargo build --features="no_hotspot"
    cp target/debug/wifi-connect .

#    RUST_LOG=error ./wifi-connect

    #to find /sbin/ifconfig on the pi by default.
    export PATH="$PATH:/sbin/" 

    pidof wifi-connect | xargs kill -9 || true

    echo "Run local"
    ./wifi-connect --portal-gateway=192.168.1.180 --config-file=config/cfg.mac --auth-file=config/auth.json
fi
