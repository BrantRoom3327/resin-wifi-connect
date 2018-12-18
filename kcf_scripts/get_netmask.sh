#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    ifconfig $1 | grep netmask | awk '{print $4}'
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "255.255.255.0"
fi

#apparently this doens't work in the container, but does work in the hostOS, no idea why...
#ifconfig "$1" | sed -rn '2s/ .*:(.*)$/\1/p'

