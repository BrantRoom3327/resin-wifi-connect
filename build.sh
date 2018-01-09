#!/bin/bash
set -e

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -r|--release)
    RELEASE=1
    shift # past arg 
    ;;
esac
done

#echo RELEASE = "${RELEASE}"

if [ "${RELEASE}" == "1" ]; then
    #build the release for docker push
    scripts/local-build.sh x86_64-unknown-linux-gnu
    docker build --rm -t wifitest .
else 
    #run a debug build, default
    cargo build --features="localbuild"
    cp target/debug/wifi-connect .
    ./wifi-connect
fi