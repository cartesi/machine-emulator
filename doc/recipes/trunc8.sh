#!/bin/bash
sed -E 's/^0[xX]//' | head -c 8
