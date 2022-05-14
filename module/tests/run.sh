#!/bin/bash
set -e

# Optional overrides
: ${NIXMODULE:=`which nixmodule`}
: ${NIXMODULEARGS:=""}

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
    $NIXMODULE $NIXMODULEARGS
else
    $NIXMODULE --debug $NIXMODULEARGS
fi

# Remove the test keys
rm /tmp/test_key* include/key.h

# Cleanup
make clean
