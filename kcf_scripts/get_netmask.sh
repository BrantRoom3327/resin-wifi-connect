#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    ifconfig $1 | grep Mask: | awk '{print $4}' | cut -d ':' -f 2
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "255.255.255.0"
fi

#fedora
#ifconfig $1 | grep netmask | awk '{print $4}'

