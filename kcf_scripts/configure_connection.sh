#!/bin/bash
#NOTE: not using set -e because calls to nmcli for connections that don't exist will fail this script
#even probing for connections cause a failure

#TODO: add some usage examples here

#See all the variables the user is setting
#DEBUG=1

while [ "$#" -gt 0 ]; do
  case "$1" in
      --interface_name=*) INTERFACE_NAME="${1#*=}"; shift 1;;
      --interface_type=*) INTERFACE_TYPE="${1#*=}"; shift 1;;
      --method=*) METHOD="${1#*=}"; shift 1;;
      --ssid=*) SSID="${1#*=}"; shift 1;;
      --psk=*) PSK="${1#*=}"; shift 1;;
      --ip_address=*) IP_ADDRESS="${1#*=}"; shift 1;;
      --gateway=*) GATEWAY="${1#*=}"; shift 1;;
      --dns_entries=*) DNS_ENTRIES="${1#*=}"; shift 1;;
      --metric=*) METRIC="${1#*=}"; shift 1;;
      --disable=*) DISABLE="${1#*=}"; shift 1;;
      -*) echo "unknown option: $1" >&2; exit 1;;
       *) handle_argument "$1"; shift 1;;
  esac
done

COMMANDS=()
#
#some basic error checking
#

#make sure wifi or ethernet is specified, unless doing a disable
if [ "$INTERFACE_TYPE" != "wifi" ] && [ "$INTERFACE_TYPE" != "ethernet" ] && [ "$DISABLE" == "" ]; then
    echo "ERROR, only 'wifi' or 'ethernet' allowed for interface type"
    exit 1
fi 

#make sure if wifi is specified that the ssid and psk is also specified
if [ "$INTERFACE_TYPE" == "wifi" ]; then
    if [ "$SSID" == "" ]; then
        echo "For wifi you must specify --ssid "
        exit 2
    fi
    if [ "$PSK" == "" ]; then
        echo "For wifi you must specify --psk"
        exit 2
    fi
fi 

#make sure one of dhcp or static is set
if [ "$METHOD" != "dhcp" ] && [ "$METHOD" != "static" ] && [ "$DISABLE" == "" ]; then
    echo "ERROR, only 'dhcp' or 'static' allowed for "
    exit 3 
fi 

#if we are using static make sure we have an $IP_ADDRESS, $GATEWAY and $DNS_ENTRIES
if [ "$METHOD" == "static" ]; then
    if [ "$IP_ADDRESS" == "" ]; then
        echo "Must specify an --ip_address for static config"
        exit 4
    fi

    if [ "$GATEWAY" == "" ]; then
        echo "Must specify a --gateway for static config"
        exit 5
    fi

    if [ "$DNS_ENTRIES" == "" ]; then
        echo "Must specify a --dns_entries for static config"
        exit 6
    fi
fi 

#TODO: add metric check, 1-1024 is valid only

if [ "$DEBUG" == "1" ]; then
    echo -e "\nConfiguration\n---------------"
    echo "interface name: $INTERFACE_NAME"
    echo "interface type: $INTERFACE_TYPE"
    echo "method: $METHOD"
    echo "ssid: $SSID"
    echo "psk: $PSK"
    echo "ip address: $IP_ADDRESS"
    echo "gateway: $GATEWAY"
    echo "dns: $DNS"
    echo "metric: $METRIC"
    echo "disable: $DISABLE"
    echo ""
fi

#if we are disabling an interface just delete it
if [ "$DISABLE" != "" ]; then
    COMMANDS+=("nmcli con del $INTERFACE_NAME")
    if [ "$ECHO_COMMANDS_ONLY" == "1" ]; then
        echo -e $COMMANDS
    else
        #run commands
        ${COMMANDS}
    fi

    #bail
    exit
fi

if [ "$METHOD" == "dhcp" ]; then
    if [ "$INTERFACE_TYPE" == "ethernet" ]; then
        COMMANDS+=("nmcli con del $INTERFACE_NAME")
        COMMANDS+=("nmcli con add type $INTERFACE_TYPE con-name $INTERFACE_NAME ifname $INTERFACE_NAME")
    elif [ "$INTERFACE_TYPE" == "wifi" ]; then
        #COMMANDS+=("nmcli con del $INTERFACE_NAME")
        #COMMANDS+=("nmcli dev wifi connect '$SSID' password '$PSK' ifname $INTERFACE_NAME con-name $INTERFACE_NAME")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ipv4.method auto")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ssid '$SSID'")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME wifi-sec.key-mgmt wpa-psk")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME wifi-sec.psk '$PSK'")
        COMMANDS+=("nmcli con up $INTERFACE_NAME")  #apply the settings or they will NOT stick on reboot
    fi
fi

if [ "$METHOD" == "static" ]; then
    if [ "$INTERFACE_TYPE" == "ethernet" ]; then
        COMMANDS+=("nmcli con del $INTERFACE_NAME")
        COMMANDS+=("nmcli con add type $INTERFACE_TYPE con-name $INTERFACE_NAME ifname $INTERFACE_NAME ip4 $IP_ADDRESS/24 gw4 $GATEWAY")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ipv4.dns '$DNS_ENTRIES'")
    elif [ "$INTERFACE_TYPE" == "wifi" ]; then
        #COMMANDS+=("nmcli con del $INTERFACE_NAME")
       # COMMANDS+=("nmcli con add type $INTERFACE_TYPE con-name $INTERFACE_NAME ifname $INTERFACE_NAME ssid '$SSID' ip4 $IP_ADDRESS/24 gw4 $GATEWAY")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ip4 $IP_ADDRESS/24 gw4 $GATEWAY")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ssid '$SSID'")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME wifi-sec.key-mgmt wpa-psk")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME wifi-sec.psk '$PSK'")
        COMMANDS+=("nmcli con mod $INTERFACE_NAME ipv4.method manual")
        COMMANDS+=("nmcli con up $INTERFACE_NAME")  #apply the settings or they will NOT stick on reboot
    fi
fi

#set 'ip route show' metric
if [ "$METRIC" != "" ]; then
    COMMANDS+=("nmcli con mod $INTERFACE_NAME ipv4.route-metric $METRIC")
else
    COMMANDS+=("nmcli con mod $INTERFACE_NAME ipv4.never-default true")
fi

#send commands to output or just run them
if [ "$ECHO_COMMANDS_ONLY" == "1" ]; then
   declare -p COMMANDS
else
  for (( i=0; i< ${#COMMANDS[@]}; i++)); do
    eval "${COMMANDS[$i]}"
  done
fi
