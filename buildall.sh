#!/bin/bash
scripts/local-build.sh x86_64-unknown-linux-gnu
docker build --rm -t wifitest .
