#!/bin/bash

cartesi-machine --store-config 2>&1 |
    grep bootargs |
    sed 's/.* = //' |
    sed 's/,$//'
