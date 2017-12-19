#!/bin/bash
docker run -it --cap-add=SYS_ADMIN -e "container=docker" --privileged --tmpfs /run --tmpfs /run/lock --net=host -v /sys/fs/cgroup:/sys/fs/cgroup wifitest /usr/sbin/init
