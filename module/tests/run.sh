#!/bin/bash
set -e

# Optional override
: ${NIXMODULE:=`which nixmodule`}

# build usermode tools
pushd ../tools
cross build --target x86_64-unknown-linux-musl --release
popd

# generate keys
pushd include
../../tools/target/x86_64-unknown-linux-musl/release/db keygen --out /tmp/test_key
popd

# Run the test
if [[ -z "${DEBUG}" ]]; then
    $NIXMODULE
else
    $NIXMODULE
fi

# Remove the test keys
rm /tmp/test_key* include/key.h
