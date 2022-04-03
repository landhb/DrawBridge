#!/bin/bash
set -e

# build usermode tools
pushd tools
cross build --target x86_64-unknown-linux-musl --release
popd

# generate keys
pushd include
../tools/target/x86_64-unknown-linux-musl/release/db keygen --out /tmp/test_key
popd

# Run the test
if [[ -z "${DEBUG}" ]]; then
    out-of-tree pew --test=tests/test.sh
else
    out-of-tree debug --kernel Ubuntu:5.11*
fi

# Remove the test keys
rm test_key* key.h
