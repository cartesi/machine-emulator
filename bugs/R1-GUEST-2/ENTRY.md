## R1-GUEST-2

**Title.** `rollup --utf8-payload accept|reject|finish` consumes an advance-state input whose payload is not valid
UTF-8, then exits 1 without printing the request. An input sender can make an application that uses the tool as the
manual shows halt, or accept an input it never saw.

**Severity.** Critical (preferred reading). Low under the reading that `--utf8-payload` is documented only for
payloads that are UTF-8 text (see Rating).

### Problem

`rollup accept` (and `reject` and `finish`) first calls `cmt_rollup_finish`. That call yields manually with the
accepted (or rejected) reason and receives the next request into the rx buffer. Only after that does the tool build
its JSON output. In `--utf8-payload` mode, `encode_payload` returns the raw payload bytes as a `std::string`, and
`nlohmann::json::dump(2)` runs with its default strict error handler, so it throws `type_error.316` on any invalid
UTF-8 byte. `finish_request_and_get_next` catches the exception, prints it to stderr, and returns 1. Nothing is
printed on stdout.

By then the input has been delivered and the yield that answered the previous one has completed. The application gets
no request and exit status 1. It cannot tell this from a failure that happened before the yield, and the tool
documents no failure after the input is consumed. What happens next depends on how the application handles errors:

- If it stops when the tool fails (`exit`, `set -e`), cartesi-init halts the machine. The application then deviates
  from the rollup interface: it does not yield manually with the accepted or rejected reason after that input.
  Every later input is lost. Under A5, the outputs of the halted state cannot be extracted.
- If it retries `rollup accept`, the tool accepts the consumed input. The application never saw it and emitted
  nothing for it.
- If it continues with `rollup reject`, as the manual's `calc.sh` does when anything in its loop fails, the input is
  rejected whatever it contains.

Section 1 requires that no adversary can make a correctly designed application settle a state other than the one
the state transition function defines. Section 3 counts a guest-software defect that lets an input make such an
application deviate from the rollup interface as an R7 deviation in the rx buffer and the yield interface. Any
input sender can trigger this one with a single payload byte such as `0xff`.

### Component, role and area

`machine-guest-tools` v0.18.1-test1, the `rollup` command-line tool in the guest root file system (the
`rootfs-tools.ext2` that the harness pins as `rootfs.ext2`). Role from the AUDIT.md table: "`machine-guest-tools`
v0.18.1-test1 | Guest software". Area: encoding the payload of the next request in `--utf8-payload` mode after the
`finish` yield.

### Location

`sys-utils/rollup/rollup.cpp` in machine-guest-tools v0.18.1-test1:

- `encode_payload`: for `encoding::utf8` it returns `{data, length}` without validating or escaping the bytes.
- `write_advance_state` (and `write_inspect_state`): `std::cout << j.dump(2)`. nlohmann's strict handler throws
  `type_error.316` for invalid UTF-8.
- `finish_request_and_get_next`: `cmt_rollup_finish(r, &f)` (the yield, which receives the input) runs before
  `write_advance_state`. The `catch` prints `x.what()` and returns 1.

### Evidence and test

`bugs/R1-GUEST-2/` contains `test.lua` (the test) and `README.md` (description, the documented scope of
`--utf8-payload`, and the expected output). There are no other support files. The test uses the harness config
`linux-rootfs` (harness `linux.bin` with the pinned guest-tools `rootfs.ext2`) and sets the entrypoint to a shell echo
application. The application calls `rollup --utf8-payload accept|reject` and checks its exit status. It prints each
request's payload, emits the payload as a notice and accepts. If the tool returns no request, it prints a message
and exits 3. The test delivers four advance-state inputs through the machine API (`send_cmio_response` with
`harness.encode_advance`): `hello`, `h\xc3\xa9llo` (valid UTF-8), `h\xffllo` (invalid UTF-8) and `bye`. The first two
are controls and must each be accepted with one notice, otherwise the test exits 2. **Asserted:** after each input,
the machine reaches a manual yield with the accepted or the rejected reason. A second run, which is informative and
not asserted, uses an application that retries `rollup accept` when it fails.

Run `bugs/run.sh R1-GUEST-2` (about 4 s, two short Linux boots). On audit/prt2 it prints (excerpt):

```
[stop on failure] input 1 (payload "hello"): accepted, 1 output(s) emitted
[stop on failure] input 2 (payload "héllo"): accepted, 1 output(s) emitted
[stop on failure] input 3 (payload "h\255llo"): halted, 0 output(s) emitted
[stop on failure] guest console: [json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xFF
[stop on failure] guest console: app: rollup --utf8-payload accept failed: no request obtained, stopping
VIOLATION: after input 3 (payload "h\255llo", not valid UTF-8) the machine halted instead of yielding manually with the accepted or the rejected reason
  cause: `rollup --utf8-payload accept` received the input (its accept yield returned) and then failed to print it: nlohmann type_error.316 (invalid UTF-8), exit 1, empty stdout
[retry on failure] input 3 (payload "h\255llo"): accepted, 0 output(s) emitted
[retry on failure] input 4 (payload "bye"): accepted, 1 output(s) emitted
INFO: with retry, input 3 was ACCEPTED with no notice: the application never saw it
run.sh: R1-GUEST-2: exit 1 (bug present)
```

Exit status 1. The prover reported four runs with exit 1, and the reviewer re-ran it twice with exit 1. The test
exits 0 once the tool prints a request for such a payload (by escaping, replacement or a documented fallback
encoding), or once it ends that input at an accepted or rejected yield in some other defined way. No fallback model
was used. The candidate was found by a hunter (angle GUEST), proved by a prover and reviewed, all on Opus 5.5.

### Trigger and reachability

Any input sender can trigger it. Threat model section 4: "input senders (any bytes, any count)". The sender sends
an advance-state input whose payload contains a byte sequence that is not valid UTF-8, such as `0xff`. The input
box ABI-encodes any payload, and a small payload fits in the rx buffer, so the delivery changes the state (R5). The
application only has to use `rollup --utf8-payload accept`, `reject` or `finish`. The manual's rolling calculator
`calc.sh` (doc/README.md) uses exactly these commands, and the PRT recipes run it. No special machine state is needed.
The input is the first one processed after any accepted or rejected yield.

### Rating

1. Out of scope: no exclusion covers it. "The stall of an application that halts ..." excludes what an application
   loses by halting on its own. Here an input makes guest software that section 3 puts in scope cause the halt.
   "An application that is not correctly designed, other than through a defect in guest software that section 3
   puts in scope" and "Guest software that an input can subvert, as long as R7 and R8 hold, other than the defects
   that section 3 puts in scope" both defer to section 3 (step 2). The trigger is an ordinary input. It needs no
   machine API call by an untrusted party, no snapshot and no violation of a deployment obligation.
2. Role: Guest software (AUDIT.md: "`machine-guest-tools` v0.18.1-test1 | Guest software"). Section 3, which
   covers this component: "A defect in them is in scope only where an application depends on them as documented,
   and would be correctly designed if they worked as documented. A defect that lets an input make such an
   application deviate from the rollup interface is Critical, as an R7 deviation in the rx buffer, the tx buffer and
   the yield interface. Any other defect in them is Low."
3. High and Medium cases: none fits. The listed High and Medium cases are about verifiers, path divergences,
   emulator crashes, honest-operator components, reproducible builds, version detection, constant-factor cost,
   support components, the machine API, hash integrity and persistence. None concerns guest software. Section 3
   gives guest software only Critical or Low.
4. Critical: the guest-software clause applies. The test's application uses only documented commands and options.
   `rollup --help`, quoted in the manual, says `finish` (and its shortcuts `accept` and `reject`) "print the next
   request to stdout", with "<data> contains arbitrary data in the selected payload encoding", and documents no
   failure after the request is received. If the tool worked as documented, the application would print, emit and
   accept every input. It would then meet section 2 ("After each input, it yields manually with the accepted or the
   rejected reason"), so it is correctly designed. A single input makes it halt instead, which is a deviation from
   the rollup interface. The obligation broken is section 2's correctly designed application, which section 3
   rates "as an R7 deviation in the rx buffer, the tx buffer and the yield interface". With retry-on-failure error
   handling, the consumed rx-buffer contents never reach the application before it accepts.

Two readings give different classes:

- **Reading A, Critical (preferred).** Using `--utf8-payload` in an application that receives inputs from anyone is
  documented use. The manual's own canonical rollup application, `calc.sh`, uses `rollup --utf8-payload
  accept/reject` on untrusted inputs, and the help text promises that `finish` prints the next request. The manual's
  sentence "Use the default 0x-prefixed hex or `--base64-payload` instead when payloads contain arbitrary binary
  data rather than text" is about the host encoder `cartesi-rollup-data.lua`, where the developer chooses the
  payloads. It does not tell an application to expect its tool to consume an input and print nothing.
- **Reading B, Low.** The option is documented as "encode/decode <data> fields in JSON values as UTF-8 text". A
  JSON string cannot carry invalid UTF-8, and the manual advises hex or base64 for arbitrary binary data. Under
  this reading, an application that selects a text-only encoding while senders can send any bytes is "outside its
  intended use" (section 8, Low: "a defect in guest software that only an application outside its intended use
  can reach"). Also, the manual's own `calc.sh` survives the input: when its loop fails, it calls `rollup reject`
  next, which rejects the consumed input.

Deciding facts: whether the guest `rollup` tool's documented contract for `--utf8-payload` covers advance-state
payloads that are not UTF-8 text (the help text says neither yes nor no), and whether an application may treat a
nonzero exit of `rollup accept` as fatal. Nothing in the tool's documentation says that a failure can follow a
completed yield. I prefer A because the manual presents `--utf8-payload` as the way to write the calculator, a rollup
application exposed to arbitrary senders, and because the defect is reached through the input, not through misuse by
the application.

### Possible solution and risks

Make the tool's output total in `--utf8-payload` mode. Options:

- (a) Dump with `nlohmann::json::error_handler_t::replace`. This is lossy: the application sees U+FFFD instead of the
  bytes, so two different payloads can look the same to it.
- (b) Fall back to a lossless, documented representation for non-UTF-8 payloads, such as hex with a flag field.
  Applications must handle the new shape.
- (c) Add a documented error path that reports, on stdout or through a distinct exit status, that the request was
  received but could not be encoded, so the application can still reject it.

Whatever the choice, document that any nonzero exit of `finish`, `accept` or `reject` after the yield means the
input was consumed. Apply the same review to the other places that print payload-derived JSON (`write_inspect_state`,
`gio`). The risks are behavioral changes for existing applications that parse the output. Option (a) may hide
attacker-controlled differences between payloads from the application.

### Risk of not fixing it

Any input sender can halt, with one non-UTF-8 byte, every application that uses `rollup --utf8-payload` and stops
when the tool fails. All later inputs are then lost and the outputs become unprovable (A5). An application that
retries instead accepts an input it never processed. Applications that, like `calc.sh`, carry on with `rollup
reject` only lose the input. Outside the code, the mitigation is to use the default hex or `--base64-payload`
encoding in the guest, or to treat every failure of `rollup accept/reject/finish` as "input consumed, reject it".
