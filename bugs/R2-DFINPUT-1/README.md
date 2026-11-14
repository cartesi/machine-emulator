# R2-DFINPUT-1: manual's /dev/cmio section puts the request type in `data`; the emulator puts it in `reason`

## What is asserted

The test boots Linux with the pinned machine-guest-tools rootfs (`bugs/harness/work/configs/linux-rootfs`). It
runs the guest-tools `yield` utility as the entrypoint: `CMT_DEBUG=1 yield manual rx-accepted 0`. That utility
wraps `IOCTL_CMIO_YIELD` on `/dev/cmio` directly, and with `CMT_DEBUG=1` libcmt prints the
`struct cmio_yield` that the ioctl returns. The host delivers one advance-state input of L = 324 bytes with
`send_cmio_response` and runs the machine to the halt. The test then checks the guest-visible struct and the
`htif_fromhost` register against both of the manual's statements about this response. It checks each statement
only while `doc/README.md` still contains it:

- **HTIF yield section:** "The `REASON` field in `fromhost` carries the request type, and the `DATA` field
  carries the request length in bytes."
- **"The /dev/cmio device" section:** for `HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED`, "the host sets the `data`
  field on resume to `HTIF_YIELD_REASON_ADVANCE_STATE` or `HTIF_YIELD_REASON_INSPECT_STATE` to indicate the type
  of the freshly loaded input in the receive buffer".

With L != 0, both statements cannot hold at once. The emulator, libcmt and the HTIF section agree. The
`/dev/cmio` sentence does not.

## Requirement

- THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents
  them, departing only where the manual documents a deviation. ... The rx buffer, the tx buffer, and the yield
  interface (contents, lengths, and reason encoding)."
- THREAT_MODEL.md section 8: "A contradiction between the manual and the behavior on a security-relevant point is
  a defect in one of the two. It takes the severity it would have if the manual were right."

## How to run

```sh
bugs/run.sh R2-DFINPUT-1      # about 5 s
```

To check that the test passes once the manual is fixed, point `R2_DFINPUT_1_MANUAL` at a copy of
`doc/README.md` whose `/dev/cmio` sentence says that `reason` carries the type and `data` the length. On that
copy the test exits 0. This was checked with such a copy.

## Expected output on audit/prt2 (exit 1)

```
manual: /dev/cmio statement present=true, HTIF statement present=true
delivered advance-state input of L=324 bytes; fromhost=0x0000000000000144 (REASON=0 DATA=324)
guest /dev/cmio struct cmio_yield after resume: .reason=0 .data=324
OK: manual HTIF section: REASON = request type (0) and DATA = request length (324); ...
VIOLATED: manual /dev/cmio section: on resume from rx-accepted the host sets the `data` field to the request type (HTIF_YIELD_REASON_ADVANCE_STATE = 0); observed guest .data=324 (the input length), .reason=0
run.sh: R2-DFINPUT-1: exit 1 (bug present)
```

Exit 2 means a setup problem: the configuration or rootfs is missing, the guest does not reach the yield, the
libcmt debug output cannot be found, or the manual was reworded so that neither statement is found.
