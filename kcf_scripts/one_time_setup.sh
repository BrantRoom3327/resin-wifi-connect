#!/bin/bash

#path to app inside container
source /usr/src/app/kcf_scripts/defines

#eth0, dhcp
nmcli con add type ethernet con-name $ETH0 ifname $ETH0
nmcli con mod $ETH0 ipv4.route-metric 1

#eth1, static
nmcli con add con-name $ETH1 ifname $ETH1 type ethernet ip4 192.168.151.100/24 gw4 192.168.151.100

#disable the wired connection as preferred, we want to bring up the $ETH0 interface as default in place of it
#will this be possible to switch at startup?
nmcli con mod "Wired connection 1" ipv4.never-default true

