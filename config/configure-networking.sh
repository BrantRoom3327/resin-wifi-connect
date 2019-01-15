#!/bin/bash
#NOTE: not using set -e because calls to nmcli for connections that don't exist will fail

DBUS_CONTAINER=/host/run/dbus/system_bus_socket
DBUS_LOCAL=/var/run/dbus/system_bus_socket

#see if /host or /var dbus exists, prefer /host since that is for the container on resin
if [ -e $DBUS_CONTAINER ]; then
    echo "Using dbus socket -> $DBUS_CONTAINER"
    export DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_CONTAINER
elif [ -e $DBUS_LOCAL ]; then
    echo "Using dbus socket -> $DBUS_LOCAL"
    export DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_LOCAL
else
    echo "No dbus socket found! Exiting.."
    exit
fi

#set to 1 if you only want to echo but not execute commands
export ECHO_COMMANDS_ONLY=0

kcf_scripts/configure_connection.sh --interface_name=en0 --disable=1
kcf_scripts/configure_connection.sh --interface_type=wifi --method=static --interface_name=blah-invalid --ssid=HouseOfDoon --psk=asfasdfasdf  --ip_address=192.168.1.123 --gateway=192.168.1.1  --dns_entries='8.8.8.8 '  --metric=1
kcf_scripts/configure_connection.sh --interface_type=ethernet --method=static --interface_name=en1 --ip_address=192.168.151.100 --gateway=192.168.151.100  --dns_entries='8.8.8.8 ' 

kcf_scripts/reboot.sh
