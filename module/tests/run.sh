#!/bin/bash

# Optional overrides
: ${NIXMODULE:=`which nixmodule`}
: ${NIXMODULEARGS:=""}

# build usermode tools
pushd ../tools
cargo build --target x86_64-unknown-linux-musl --release
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

# For Github actions
code=$?
build=2
insmod=2
test=2
echo "Exited with $code";

# If success all =1
if [ $code == 0 ]; then build=1 && insmod=1 && test=1; fi;

# If BuildError, then build failed and rest are N/A
if [ $code == 4 ]; then build=0 && insmod=2 && test=2; fi;

# If InsmodError, then success, fail, N/A
if [ $code == 5 ]; then build=1 && insmod=0 && test=2;  fi;

# If TestError, then success, success, fail
if [ $code == 6 ]; then build=1 && insmod=1 && test=0; fi;

echo "Set build=$build insmod=$insmod test=$insmod"; \
if [ $build == 2 ]; then echo "##[set-output name=build;]N/A" && echo "##[set-output name=buildc;]grey"; fi;
if [ $insmod == 2 ]; then echo "##[set-output name=insmod;]N/A" && echo "##[set-output name=insmodc;]grey"; fi;
if [ $test == 2 ]; then echo "##[set-output name=test;]N/A" && echo "##[set-output name=testc;]grey"; fi;
if [ $build == 1 ]; then echo "##[set-output name=build;]Passing" && echo "##[set-output name=buildc;]green"; fi;
if [ $insmod == 1 ]; then echo "##[set-output name=insmod;]Passing" && echo "##[set-output name=insmodc;]green"; fi;
if [ $test == 1 ]; then echo "##[set-output name=test;]Passing" && echo "##[set-output name=testc;]green"; fi;
if [ $build == 0 ]; then echo "##[set-output name=build;]Failed" && echo "##[set-output name=buildc;]red"; fi;
if [ $insmod == 0 ]; then echo "##[set-output name=insmod;]Failed" && echo "##[set-output name=insmodc;]red"; fi;
if [ $test == 0 ]; then echo "##[set-output name=test;]Failed" && echo "##[set-output name=testc;]red"; fi;

# Remove the test keys
rm /tmp/test_key* include/key.h

# Cleanup
make clean

# This script should technically always "succeed" so that the
# badges are generated
echo "##[set-output name=realexit;]$code"
exit 0