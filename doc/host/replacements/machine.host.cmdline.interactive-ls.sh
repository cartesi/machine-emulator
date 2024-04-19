#!/bin/bash
cartesi-machine -i -- sh 2>&1 <<EOF
ls /bin
exit
EOF
