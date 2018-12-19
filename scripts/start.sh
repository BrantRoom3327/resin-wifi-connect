#!/usr/bin/env bash
#This script is meant to be run inside the docker container on resin.io
set -e

export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket

#copy collectorsettings.xml if it doesnt exist
[ -f /data/collectorsettings.xml ] || cp config/collectorsettings.xml /data/
if [ ! -f /data/one_time_setup.sh ]; then
    echo "Run one time setup"
    cp kcf_scripts/one_time_setup.sh /data

    #run the one time setup script
    /data/one_time_setup.sh
fi

#create a configure-networking.sh script, same as in cfg.json.  
#set it executable, we write it out at runtime
touch /data/configure-networking.sh
chmod +x /data/configure-networking.sh

##### start the app ####

#start udhcpd
udhcpd kcf_scripts/udhcpd.conf &

#run the correct wifi-connect based on cpu arch at runtime
unamestr=`uname -m`
if [[ "$unamestr" == 'armv7l' ]]; then
    ./wifi-connect --portal-ssid=QuarterMaster --config-file=config/cfg.rpi3.resin --auth-file=config/auth.json
else
    ./wifi-connect --portal-ssid=QuarterMaster --config-file=config/cfg.intel --auth-file=config/auth.json
fi
