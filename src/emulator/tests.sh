#!/bin/sh

root_dir="$( cd "$(dirname "$0")" ; pwd -P )"
errors_count=0

cd $root_dir

for t in tests/*.bin
do 
  echo $t 
  lua run.lua --batch --boot-image=$t || errors_count=$((errors_count+1))
  if [ "$errors_count" -gt 3 ]
  then
    break
  fi
done

if [ "$errors_count" -eq 0 ]
then
  echo "SUCCESS"
else
  echo "$errors_count FAILURE(S)"
fi

exit $errors_count

