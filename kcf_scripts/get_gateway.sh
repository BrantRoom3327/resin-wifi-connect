#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    nmcli device show $1 | grep IP4.GATEWAY | awk '{print $2}'
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo "192.168.1.1"
fi

