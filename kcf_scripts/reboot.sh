#!/bin/bash
set -e

DBUS_CONTAINER=/host/run/dbus/system_bus_socket
DBUS_LOCAL=/var/run/dbus/system_dbus_socket

#see if /host or /var dbus exists, prefer /host since that is for the container on resin
if [ -e $DBUS_CONTAINER ]; then
    export DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_CONTAINER
    #we are running in a resin container, send dbus reboot command from there
    dbus-send --system --print-reply --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.Reboot

else
    #local runtime, just call reboot
    sudo reboot
fi

