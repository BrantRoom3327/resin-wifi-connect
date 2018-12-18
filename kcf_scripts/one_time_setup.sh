#!/bin/bash

#path to app inside container
source /usr/src/app/kcf_scripts/defines

#eth0, dhcp
nmcli con add type ethernet con-name $ETH0 ifname $ETH0
nmcli con mod $ETH0 ipv4.route-metric 1

#eth1, static
nmcli con add con-name $ETH1 ifname $ETH1 type ethernet ip4 192.168.151.100/24 gw4 192.168.151.100

#FIXME: This still is a problem after Resin's End of Marh 2018 fix.  We can't delete these connections
# or the vpn drops and the resin.io container can't talk to the resin.io service on the web.
#Try deleting connections after creating new ones so the VPN doesn't drop in the container.
#nmcli con del "Wired connection 1"
#nmcli con del "Wired connection 2"

#TODO: This doesn't really appear to have an effect from what i can tell.
nmcli con mod "Wired connection 1" ipv4.never-default true

