#!/bin/sh
for t in tests/*.bin; do echo $t; lua run.lua --batch --boot-image=$t || echo FAIL; done
