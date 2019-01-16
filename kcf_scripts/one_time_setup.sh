#!/bin/bash

#path to app inside container
source /usr/src/app/kcf_scripts/defines

#eth0, dhcp
nmcli con add type ethernet con-name $ETH0 ifname $ETH0
nmcli con mod $ETH0 ipv4.route-metric 1

#eth1, static
nmcli con add con-name $ETH1 ifname $ETH1 type ethernet ip4 192.168.151.100/24 gw4 192.168.151.100

#disable these connections, we will recreate connections that follow the exact device name
#the resin-wifi-01 connection causes issues on reboot trying to modify it, settings don't stick
#so for now tell nmcli to never use it
nmcli con mod "Wired connection 1" ipv4.never-default true
#nmcli con mod "resin-wifi-01" ipv4.never-default true

