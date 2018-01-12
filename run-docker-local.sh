#!/bin/bash
docker run -it --cap-add=SYS_ADMIN -e "container=docker" --privileged --net=host -v /sys/fs/cgroup:/sys/fs/cgroup --tmpfs /run --tmpfs /run/lock wifitest /usr/sbin/init
