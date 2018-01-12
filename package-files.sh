#!/bin/bash
set -e

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    #build for arm v7
    -p|--production)
    PRODUCTION=1
    shift # past arg 
    ;;
esac
done

#expected to run after a build has kicked out all the assets needed. 
#this just bundles them up for checkin in the releases folder so it can be pulled down
#by the docker image
export BUNDLE_DIR=./bundle
rm -rf $BUNDLE_DIR
mkdir $BUNDLE_DIR
cp cfg.json auth.json $BUNDLE_DIR
cp -R public $BUNDLE_DIR

if [ "${PRODUCTION}" == "1" ]; then
    #For Arm
    cp target/armv7-unknown-linux-gnueabihf/release/wifi-connect $BUNDLE_DIR
else
    #For x86_64
    cp target/x86_64-unknown-linux-gnu/release/wifi-connect $BUNDLE_DIR
fi

DATETIME=`date '+%Y-%m-%d---%H-%M-%S'`

#tar everything up and time stample it.
tar czf bundle-${DATETIME}.tgz ./bundle

echo "Created: bundle-${DATETIME}.tgz"