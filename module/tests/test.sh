#!/bin/sh
set -e

# Log dmesg output and fail
logdmesg() {
    echo $1
    dmesg | tail -n 120
    return 1 
}

check_port() {
    if nc -w1 -z 127.0.0.1 8888; then
        echo "Port is listening"
        return 0
    else
        echo "Port is not listening"
        return 1
    fi
}

# check that module has loaded
dmesg | grep "drawbridge: Loaded module" || logdmesg "[!!!] Load Failed!"

# Start the service to guard
nc -nlvp 8888 &
nc_pid=$!

# Check that service is closed
if check_port; then
    echo "Port appears open pre-auth"
    exit 1
fi

# run auth packet
db auth -i /tmp/test_key --server 127.0.0.1 --dport 53 -p udp --unlock 8888

# Verify the auth worked
dmesg | grep "drawbridge: Authentication" || logdmesg "[!!!] Auth Failed!"

# Check that port is now open
if [ ! check_port ]; then
    echo "Port is still not accessible after auth."
    exit 1
fi

# Wait for reaper thread timeout
sleep 60

# Test that nc is still running
if ps -p $nc_pid > /dev/null
then
    echo "$nc_pid is running"
else
    exit 1
fi

# Check that service is closed again
if check_port; then
    echo "Port is still open after 30 seconds"
    exit 1
fi

# Cleanup nc
kill -9 $nc_pid 
exit 0