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
../../tools/target/x86_64-unknown-linux-musl/release/db keygen -a rsa -b 4096 --out /tmp/test_key
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
if [ $build == 2 ]; then echo "{build}=N/A" >> $GITHUB_OUTPUT && echo "{buildc}=grey" >> $GITHUB_OUTPUT; fi;
if [ $insmod == 2 ]; then echo "{insmod}=N/A" >> $GITHUB_OUTPUT  && echo "{insmodc}=grey" >> $GITHUB_OUTPUT; fi;
if [ $test == 2 ]; then echo "{test}=N/A" >> $GITHUB_OUTPUT && echo "{testc}=grey" >> $GITHUB_OUTPUT; fi;
if [ $build == 1 ]; then echo "{build}=Passing" >> $GITHUB_OUTPUT  && echo "{buildc}=green"  >> $GITHUB_OUTPUT; fi;
if [ $insmod == 1 ]; then echo "{insmod}=Passing" >> $GITHUB_OUTPUT  && echo "{insmodc}=green"  >> $GITHUB_OUTPUT; fi;
if [ $test == 1 ]; then echo "{test}=Passing" >> $GITHUB_OUTPUT  && echo "{testc}=green" >> $GITHUB_OUTPUT; fi;
if [ $build == 0 ]; then echo "{build}=Failed" >> $GITHUB_OUTPUT  && echo "{buildc}=red" >> $GITHUB_OUTPUT; fi;
if [ $insmod == 0 ]; then echo "{insmod}=Failed" >> $GITHUB_OUTPUT  && echo "{insmodc}=red" >> $GITHUB_OUTPUT; fi;
if [ $test == 0 ]; then echo "{test}=Failed" >> $GITHUB_OUTPUT && echo "{testc}=red" >> $GITHUB_OUTPUT; fi;

# Remove the test keys
rm /tmp/test_key* include/key.h

# Cleanup
make clean

# This script should technically always "succeed" so that the
# badges are generated
echo "##[set-output name=realexit;]$code"
exit 0