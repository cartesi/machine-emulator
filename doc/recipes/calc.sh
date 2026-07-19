#!/bin/bash
set -o pipefail

declare -A emit=([advance_state]=notice [inspect_state]=report)
reqfile=$(mktemp /tmp/calc.XXXXXX)
status="accept"
while :
do
  rollup --utf8-payload "$status" > "$reqfile"
  request_type=$(jq -j .request_type < "$reqfile")
  status="reject"
  jq -jr '.data.payload' < "$reqfile" | \
      bc | \
        grep . | \
          tr -d '\\\n' | \
            jq -Rs '{ payload: . }' | \
              rollup --utf8-payload "${emit[$request_type]}" > /dev/null && \
                  status="accept"
done
rm "$reqfile"
