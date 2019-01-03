#!/bin/bash

if [ $# -ne 1 ]; then
    echo "You must pass a valid network interface name (e.g. eth0)"
    exit
fi

#pass the name of a connection, get the name back if it exists in Network Manager already
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    nmcli con show $1 | grep connection.id | awk '{print $2}'
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo $1
fi
