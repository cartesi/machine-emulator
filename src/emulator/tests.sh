#!/bin/sh
root_dir="$( cd "$(dirname "$0")" ; pwd -P )"
cd $root_dir
lua run.lua --batch --boot-image=tests/rv64um-v-divw.bin
#for t in tests/*.bin; do echo $t; lua run.lua --batch --boot-image=$t || echo FAIL; done
