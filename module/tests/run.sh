#!/bin/bash
set -e

# Optional overrides
: ${NIXMODULE:=`which nixmodule`}
: ${NIXMODULEARGS:=""}

# build usermode tools
pushd ../tools
cargo build
popd

# generate keys
pushd include
../../tools/target/debug/db keygen --out /tmp/test_key
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
