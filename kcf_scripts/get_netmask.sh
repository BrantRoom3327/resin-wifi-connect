#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

#returns the number of bits in the mask, so 24 means "255.255.255.0"

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    nmcli device show $1 | grep IP4.ADDRESS | awk '{print $2}' | cut -d '/' -f 2
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "24"
fi
