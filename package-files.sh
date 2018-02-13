#!/bin/bash
set -e

#NOTE: Deprecated.  The dockerfile.template will bundle everything we need for this app to run already.

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -p|--production)
    PRODUCTION=1
    shift # past arg 
    ;;
esac
done

export BUNDLE_DIR=./bundle
rm -rf $BUNDLE_DIR
mkdir $BUNDLE_DIR

cp -R data $BUNDLE_DIR
cp -R ui $BUNDLE_DIR

if [ "${PRODUCTION}" == "1" ]; then
    cp target/x86_64-unknown-linux-gnu/release/wifi-connect $BUNDLE_DIR
else
    cp target/armv7-unknown-linux-gnueabihf/release/wifi-connect $BUNDLE_DIR
fi

DATETIME=`date '+%Y-%m-%d---%H-%M-%S'`

#tar everything up and time stample it.
tar czf releases/bundle-${DATETIME}.tgz $BUNDLE_DIR
rm -rf $BUNDLE_DIR

echo "Created: bundle-${DATETIME}.tgz"
