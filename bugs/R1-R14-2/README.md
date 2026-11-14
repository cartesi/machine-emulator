# R1-R14-2: the manual does not state the host output-channel requirement

## Requirement

THREAT_MODEL.md, section 4, "The operator's host is provisioned":

> Host output channels, such as the console, accept every write the emulator makes, blocking if needed, and the
> manual must state this requirement.

## What the test asserts

`test.lua` splits `doc/README.md` (the manual) into paragraphs, with blockquote markers removed, and looks for one that
names the console or a host output channel, speaks of blocking (with unrelated senses such as "blockchain",
"block device" and "block number" removed first), and speaks of writes. It exits 1 when no paragraph does, and 0 once
one does. Before scanning, it checks that the detector accepts the threat model's own sentence and rejects an
unrelated one, and it exits 2 if that check fails.

It also prints some context that never affects the exit status. A hand-assembled bare-metal guest prints 262144 line
feeds through HTIF putchar. With the console set to `to_null`, it runs to its halt. With the console set to `to_fd` on a
non-blocking pipe that nobody reads, `machine:run()` raises `console output flush failed: Resource temporarily
unavailable` once the pipe fills (about 64 KiB). This shows that the emulator relies on the requirement the manual
leaves out. The threat model lets a host fault stop the honest operator, so this behavior is not asserted.

`R1_R14_2_MANUAL=<path>` points the check at an edited copy of the manual. A copy with one added paragraph ("The host
must accept every write the emulator makes to its output channels, such as the console, blocking if needed. ...")
makes the test exit 0.

## Run

```sh
bugs/run.sh R1-R14-2
```

## Expected output on audit/prt2

```
context: console to_null: run ok=true break_reason=1 halted=1 mcycle=786439
context: console to_fd on a non-blocking pipe nobody reads: run ok=false result=console output flush failed: Resource temporarily unavailable halted=0 mcycle=196614
manual: 1548 paragraphs scanned, 0 state the host output-channel requirement
VIOLATED: THREAT_MODEL section 4: host output channels, such as the console, accept every write ...
run.sh: R1-R14-2: exit 1 (bug present)
```
