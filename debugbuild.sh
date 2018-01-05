#!/bin/bash
set -e
cargo build --features="localbuild"
cp target/debug/wifi-connect .
./wifi-connect
