#!/bin/sh
set -e

# Log dmesg output and fail
logdmesg() {
    echo $1
    dmesg | tail -n 120
    return 1 
}

check_port() {
    if nc -w1 -z router.eu.thethings.network 1700; then
        echo "Port is listening"
        return 0
    else
        echo "Port is not listening"
        return 1
    fi
}

# check that module has loaded
dmesg | grep "drawbridge: Loaded module" || logdmesg "[!!!] Load Failed!"

# Check that service is closed
if nc -w1 -z -u 127.0.0.1 68; then
    echo "Port is listening"
    return 1
fi

# run auth packet
db auth -i /tmp/test_key --server 127.0.0.1 --dport 53 -p udp --unlock 68

# Verify the auth worked
dmesg | grep "drawbridge: Authentication" || logdmesg "[!!!] Auth Failed!"

# Check that port is now open
if [ ! nc -w1 -z -u 127.0.0.1 68 ]; then
    echo "Port is listening"
    return 1
fi