# R1-GUEST-2: `rollup --utf8-payload accept` consumes a non-UTF-8 input, then fails with no request printed

Component: machine-guest-tools v0.18.1-test1 (the `rootfs.ext2` the harness pins), `sys-utils/rollup/rollup.cpp`.
Role: Guest software.

Cause: `encode_payload` returns the raw payload bytes in `--utf8-payload` mode, and the advance-state request is
printed with `nlohmann::json::dump(2)`, whose default strict error handler throws `type_error.316` on invalid UTF-8.
This happens after `cmt_rollup_finish` has already yielded manually with the accepted (or rejected) reason and
received the next input. The tool prints the exception to stderr, writes nothing to stdout, and exits 1. The input
has been delivered, but the application never sees it. To the application, this failure looks the same as a failed
yield.

## What the test asserts

`test.lua` boots Linux with the pinned guest-tools rootfs (harness config `linux-rootfs`). Its entrypoint is an echo
application that uses only the documented `rollup --utf8-payload` commands and checks their exit status:

```sh
s=accept
while :; do
    if ! rollup --utf8-payload "$s" > /tmp/req; then
        echo "app: rollup --utf8-payload $s failed: no request obtained, stopping"; exit 3
    fi
    echo "app: got request payload $(jq -c .data.payload /tmp/req)"
    s=reject
    jq -c '{payload: .data.payload}' /tmp/req | rollup --utf8-payload notice > /dev/null && s=accept
done
```

The test delivers these advance-state inputs through the machine API:

1. `hello`, a control.
2. `h\xc3\xa9llo` (valid non-ASCII UTF-8), a control.
3. `h\xffllo` (invalid UTF-8; any input sender can send it).
4. `bye`.

**Asserted:** after each input, the machine reaches a manual yield with the accepted or the rejected reason, not a
halt. The controls must each be accepted with one notice; if not, the test exits 2.

A second run is informative and not asserted. It uses the other natural way to handle the error, retrying
`rollup accept` when it fails. That run shows that input 3 is then **accepted with no notice**: the application never
saw the input it accepted.

Requirement: THREAT_MODEL.md, section 2, "Correctly designed application":

> On every input sequence, its guest follows the rollup interface that the manual specifies. After each input, it
> yields manually with the accepted or the rejected reason.

Section 3, Guest software:

> A defect that lets an input make such an application deviate from the rollup interface is Critical, as an R7
> deviation in the rx buffer, the tx buffer and the yield interface.

### Documented scope of `--utf8-payload` (decides severity, not reproduction)

- `rollup --help` (v0.18.1-test1) describes the option as "encode/decode <data> fields in JSON values as UTF-8
  text". For `finish` it says "print the next request to stdout ... <data> contains arbitrary data in the selected
  payload encoding".
- The manual (doc/README.md) builds its `calc.sh` example on `rollup --utf8-payload accept/reject`. In the section
  on `cartesi-rollup-data.lua` (the host-side encoder), it says: "Use the default 0x-prefixed hex or
  `--base64-payload` instead when payloads contain arbitrary binary data rather than text."
- The manual's `calc.sh` happens to survive this input. Its next loop iteration runs `rollup reject`, which rejects
  the input the tool consumed. Whether the defect matters therefore depends on how the application handles the
  tool's failure, and the tool documents no failure that happens after the input was consumed.

## How to run

```sh
bugs/run.sh R1-GUEST-2
```

It takes a few seconds (two short Linux boots).

## Expected output on audit/prt2

```
[stop on failure] input 1 (payload "hello"): accepted, 1 output(s) emitted
[stop on failure] input 2 (payload "héllo"): accepted, 1 output(s) emitted
[stop on failure] input 3 (payload "h\255llo"): halted, 0 output(s) emitted
[stop on failure] guest console: [json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xFF
[stop on failure] guest console: app: rollup --utf8-payload accept failed: no request obtained, stopping
VIOLATION: after input 3 ... the machine halted instead of yielding manually with the accepted or the rejected reason
[retry on failure] input 3 (payload "h\255llo"): accepted, 0 output(s) emitted
INFO: with retry, input 3 was ACCEPTED with no notice: the application never saw it
run.sh: R1-GUEST-2: exit 1 (bug present)
```

Exit status on audit/prt2: 1 (deterministic). The test would exit 0 if the tool encoded such payloads so that the
request is still printed, for example with escaping or replacement, or with a documented fallback encoding.
