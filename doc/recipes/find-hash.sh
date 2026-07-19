#!/bin/bash
grep -oP "\"*$1\"*: \"*\K(?:0[xX])?[a-fA-F0-9]{64}" | head -1
