#!/bin/sh

set -e

root_dir="$( cd "$(dirname "$0")" ; pwd -P )"
errors_count=0

cd $root_dir

lua tests.lua
