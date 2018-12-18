#!/usr/bin/env bash
set -e

#for use running natively on an rpi3 without any containers.
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/run/dbus/system_bus_socket
./wifi-connect --portal-gateway=192.168.1.123 --portal-ssid=QuarterMaster --config-file=config/cfg.rpi3.debug --auth-file=config/auth.json
