#!/bin/bash
cartesi-machine -i -- sh 2>&1 <<EOF
cd /bin
ls
cd /usr/bin
ls
exit
EOF
