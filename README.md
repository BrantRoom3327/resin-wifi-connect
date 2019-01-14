Altered Wifi-Connect
============

As a starting point.  Get yourself familiar with the app this application is based on.  

[resin-wifi-connect](https://github.com/resin-io/resin-wifi-connect)

The application essentially offers a wifi hotspot, with configuration for the network adapters on the system that will be applied after reboot.  The configuration is done via a webpage, which is served on the network running the hotspot.

Configuration
-------------
There are a couple configuration files to make sure are setup the way you want for the system you are targeting.  These files are:

* data/cfg.json
* config/auth.json
* scripts/start.sh
* Dockerfile.template

cfg.json
--------
This file contains the network interface names and output file names (rewritten script files using network interface names) that will be used at runtime to configure the way the system will startup.

It also contains settings related to the proxy server used by the SD Collector talk to the outside.

The top level keys you should be considering for your system are:

* "network_interfaces"
* "output_files"

For each of these groups the important keys are:

* "collector\_ethernet" - the ethernet interface (e.g. eth0) the collector will use to send data to the cloud or internal network.
* "collector\_wifi" - The wifi interface (e.g. wlan1) the sd collector will use to send data to the cloud or internal network.
* "static\_streaming\_ethernet" - The network interface used to stream data from sensors inside the installation.  This interface does not change its settings.  192.168.151.100

The same set of keys as above exist inside the "output_files" section.  Those output files must point to files in the /data/ directory as that is where resin.io stores persistent data for containers after rebooting devices.  /data/ is also the directory that the wifi-connect app looks for scripts to configure the network interface on startup.

auth.json
----------
This file contains a simple set of 'username' and 'password'.  The values given here are loaded at startup and used to authorize access to the configuration page.  They can be changed only at startup. 

start.sh
---------
This file is only used in production builds (below).  It contains all the commands that will be run when the container launches.  Make sure it is starting the wifi-connect app and exporting the path to dbus as needed by the application so that it can use NetworkMangager at runtime.

Dockerfile.template
-------------------
This file is only used in production builds (below).
Ensure the correct executable for your architecture is included in the docker container.  The cargo build outputs files into the ./target folder and is separated by architecture.

Basic Alterations to Wifi-Connect
---------------------------------
First inspect Dockerfile.template.  This is the file that gets launched by docker (Balena) when the container starts.

When the container loads for the first time and the start.sh script is executed as part of the Dockerfile.template file there is a one\_time\_setup.sh script that is run and stored in the /data/ directory of the container.  The one\_time\_setup.sh script tries to setup the container with network connection names that match the names of the adapters on the system.   It does not work for all of them right now but tries for the ethernet connections as of right now.

The wifi-connect application will run a hot spot called 'QuarterMaster' and you must connect to it to configure the network setup.  Once the user chooses which network interface (ethernet vs wifi) and the settings for that are validated the script is generated that is in charge of configuring the connection.

The script will have the parameters the user entered as well as some commands to disable connections that should not be in use.  For example, when ethernet static is setup, the wifi connection will be disabled (not the hot spot wifi) so as to avoid conflicts with configuration and routing priority conflicts.  

The script that will run configuration of network interfaces is written to the /data/ folder in the container and run before reboot.  The settings should take effect on the next reboot.  The hotspot should always be available to reconfigure the connection so long as the container is available and can get to the internet.


Building
------------

### 1. For local testing

```
# ./build.sh
```

This will build the application for x86_64 and run it.  The wifi hotspot will run on your local pc

### 2. For production

The -p is for production.

```
# ./build.sh -p 
```

Pushing builds to Balena
------------------------
Changes to the deployed resin image do not take effect for your resin app unless you push a new commit to resin.  At which point the docker container in Dockerfile.template is built.

Steps to pushing a new build:

* Make source code changes
* ```# ./build.sh -p```
* ```git add``` the source code and the target/.../wifi-connect binary to the reponsitory.
* ```git commit -m "my message"```
* ```git push balena master```

At this point the builder for balena will run and if successful will push a new container up to resin.io for deploy on the hardware.

License
-------

WiFi Connect is free software, and may be redistributed under the terms specified in
the [license](https://github.com/resin-io/resin-wifi-connect/blob/master/LICENSE).
