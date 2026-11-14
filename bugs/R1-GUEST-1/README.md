# R1-GUEST-1: the `rollup` CLI silently resets the outputs Merkle tree when /tmp/merkle.dat is gone

Component: machine-guest-tools v0.18.1-test1 (the `rootfs.ext2` the harness pins), `sys-utils/rollup/rollup.cpp`
with libcmt. Role: Guest software.

## What the test asserts

`test.lua` boots Linux with the pinned guest-tools rootfs (harness config `linux-rootfs`) and runs, as the
entrypoint, a shell application that uses only the documented `rollup` commands (`accept`/`reject`, `notice`) and
checks each command's exit status (a failing `rollup notice` makes it reject the input):

```sh
s=accept
while :; do
    rollup "$s" > /tmp/req || exit 1
    s=reject
    p=$(jq -c '{payload: .data.payload}' /tmp/req) || continue
    if [ "$CLEAN_TMP" = 1 ]; then rm -rf /tmp/* /tmp/.[!.]* 2> /dev/null; fi   # clears its scratch space
    idx=$(echo "$p" | rollup notice) || continue
    echo "app: notice index $(echo "$idx" | jq -c .index)"
    s=accept
done
```

The test delivers two advance-state inputs through the machine API, collects every `tx-output` automatic yield,
keeps the host's own outputs tree (`cartesi.hash-tree` frontier of height `ROLLUP_LOG2_MAX_OUTPUT_COUNT`, as
`cartesi-machine` does for `check_outputs_merkle_root`), and asserts that **whenever the guest accepts, the
tx-buffer root equals the root of every output accepted so far**.

- Control run (`CLEAN_TMP=0`): must accept both inputs with the right roots (notice indices 0, 1), or the test
  exits 2.
- Test run (`CLEAN_TMP=1`): the application clears /tmp after reading each request.

Trigger modeled: the application treats /tmp (a tmpfs that `cartesi-init` mounts with mode 1777 for every
process) as its own scratch space and clears it while processing an input. Neither `rollup --help` nor the manual
(doc/README.md, which itself shows the calculator keeping its request file in /tmp) says that the tool keeps state
in `/tmp/merkle.dat` or that it must survive between invocations. The cause is in the tool:
`rollup` loads the tree in its constructor and saves it in its destructor, ignoring both return values
(`cmt_rollup_load_merkle`/`cmt_rollup_save_merkle` on `/tmp/merkle.dat`), so a missing file silently becomes the
empty tree. The same silent reset follows any other loss or failed save of that file (a failed write, a short
file, a kill between the output yield and the save in the destructor); the test models only the deletion. Whether
this cleanup counts as documented use is for review (THREAT_MODEL.md section 3, Guest software; section 8 Low:
"a defect in guest software that only an application outside its intended use can reach").

## Requirement

THREAT_MODEL.md section 2, "Correctly designed application": "When it accepts, it leaves in the tx buffer the
outputs Merkle root of every output it accepted. That includes the outputs its template already commits to, and
the outputs emitted while processing the inputs it accepted." Section 3, Guest software: "A defect that lets an
input make such an application deviate from the rollup interface is Critical, as an R7 deviation in the rx buffer,
the tx buffer and the yield interface." R7: "The rx buffer, the tx buffer, and the yield interface (contents,
lengths, and reason encoding)."

Exit 0 once fixed: the tool keeps its tree where the application's scratch-space cleanup does not reach it (or
derives it otherwise), or it fails loudly (non-zero exit before emitting) so the application rejects the input.

## Run

```sh
bugs/run.sh R1-GUEST-1        # about 5 s, no artifacts written
```

## Expected output on audit/prt2

```
[control] input 2: accepted, 1 output(s) emitted, guest root 0xee05d4d6..., host root over 2 accepted output(s) 0xee05d4d6...
[control] guest console: app: notice index 0
[control] guest console: app: notice index 1
[app clears /tmp] input 1: accepted, 1 output(s) emitted, guest root 0x627f297e..., host root over 1 accepted output(s) 0x627f297e...
[app clears /tmp] input 2: accepted, 1 output(s) emitted, guest root 0x3af64fd2..., host root over 2 accepted output(s) 0xee05d4d6...
[app clears /tmp] guest console: app: notice index 0
[app clears /tmp] guest console: app: notice index 0
VIOLATION at input 2: tx-buffer root 0x3af64fd2... is not the root 0xee05d4d6... of the 2 output(s) accepted so far
  the tx-buffer root is the root of only the 1 output(s) of this input: the earlier accepted outputs were dropped from the guest's outputs tree
VIOLATED: section 2 'Correctly designed application' / ...
run.sh: R1-GUEST-1: exit 1 (bug present)
```

Every `rollup` command exited 0 (the application accepted input 2), the second notice got index 0 again, and the
accepted root omits input 1's notice, which the settled state therefore no longer commits to.

Side observation (not part of the test): two `rollup` processes in one pipeline (e.g. `rollup notice | ... |
rollup report`) do not race on the file: the second fails to open `/dev/cmio` and emits nothing.
