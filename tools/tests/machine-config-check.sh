#!/bin/bash

MACHINE_CONFIG_CPP_HASH="a412174d2150e6328812cfb1198fe362"
CURRENT_HASH=$(md5sum src/machine-config.cpp | grep -oE '[0-9a-z]{32}')

if [[ "$MACHINE_CONFIG_CPP_HASH" == "$CURRENT_HASH" ]]; then
    exit 0
fi

echo -n "You changed machine-config.cpp file. "
echo -n "Please, make sure you bumped the archive version. "
echo    "If so, change the hash in the tools/tests/machine-config-check.sh"
exit 1
