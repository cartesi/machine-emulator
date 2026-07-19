#!/bin/bash
# Print the Nth 0x-prefixed, 64-digit hex hash following the first match of PATTERN.
# Usage: hash-of.sh PATTERN [N]   (N defaults to 1)
awk -v pat="$1" -v n="${2:-1}" '
    !found && $0 ~ pat { found = 1; next }
    found && NF == 2 && length($2) == 66 && $2 ~ /^0x[0-9a-fA-F]+$/ {
        if (++i == n) { print $2; exit }
    }
'
