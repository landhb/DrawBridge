#!/bin/sh
set -e

# Log dmesg output and fail
logdmesg() {
    echo $1
    dmesg | tail
    return 1 
}

# check that module has loaded
dmesg | grep "drawbridge: Loaded module" || logdmesg "[!!!] Load Failed!"

# run auth packet
db auth -i /tmp/test_key --server 127.0.0.1 --dport 53 -p udp --unlock 8888

# Verify the auth worked
dmesg | grep "drawbridge: Authentication" || logdmesg "[!!!] Auth Failed!"