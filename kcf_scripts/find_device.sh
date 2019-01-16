#!/bin/bash

if [ $# -lt 1 ]; then
    echo "You must pass a valid network device name (e.g. eth0)"
    exit
fi

# you can pass multiple device names to this script and it will return the first in the list that 
# is found using nmcli or the network device mapper on the system

#pass the name of a connection, get the name back if it exists in Network Manager already
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then

    #trying something out
    echo "resin-wifi-01"
    exit 0

    #gather a list of all valid system device
    system_devices=$(nmcli d | awk '{print $1}') 
    for dev in $*; 
        do
            for sys_dev in $system_devices;
                do
                   if [[ $sys_dev == $dev ]]; then
                        output=$(nmcli device show $dev | grep GENERAL.DEVICE | awk '{print $2'})
                        echo $output
                        exit 0
                   fi
                done
        done
elif [[ "$unamestr" == 'Darwin' ]]; then
    echo $1
fi
