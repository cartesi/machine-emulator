#!/bin/sh
root_dir="$( cd "$(dirname "$0")" ; pwd -P )"
errors_count=0

cd $root_dir

for t in tests/*.bin; do echo $t; lua run.lua --batch --boot-image=$t || ((errors_count++)); done
echo $errors_count  

exit $?
