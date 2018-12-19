#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    ifconfig $1 | grep Mask: | awk '{print $4}' | cut -d : -f 2
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "8.8.8.8"
fi


#fedora
#    nmcli con show $1 | grep ipv4.dns: | awk '{print $2}'
