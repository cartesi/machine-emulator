# R1-R14-1: guest console output multiplies mcycle hash-collection cost with a `to_buffer` console

## What is asserted

`guest.S` is a bare-metal guest with no runtime. It stores 100000 HTIF console `putchar('\n')` back to back, about
one per mcycle (106259 mcycles in all), then halts. The test builds it into a temp dir with
`$HARNESS/baremetal/build.sh`. Each case then runs in its own child process (`child.lua`) on a fresh machine with
64 MiB RAM. Every case uses the PRT recipe geometry: a sampling period of 2^10 mcycles and bundles of 2^4 samples
(`doc/recipes/prt.lua`). The child measures only the collection's process CPU time (`os.clock`), and hashes the
initial RAM before it starts timing.

| case | collection | console |
|---|---|---|
| `roots-null` | loop over `collect_mcycle_root_hashes`, resumed after each console-output break | `to_null` |
| `roots-file` (control, slowest of 3) | same | `to_file /dev/null`, `every_line` |
| `roots-buffer` | same; the caller drains with `read_console_output` after each break | `to_buffer`, `every_line` (default flush mode) |
| `run-buffer` (information only) | same loop over `run()` | `to_buffer`, `every_line` |
| `bundle-null` | `collect_mcycle_bundle(0, 10, 4)` repeated until the halt | `to_null` |
| `bundle-file` (control, slowest of 3) | same | `to_file /dev/null`, `every_line` |
| `bundle-buffer` | same; the call has no way to drain the buffer | `to_buffer`, `when_full` |

In the `to_file` controls, the interpreter also stops at each of the 100000 newlines to flush. The difference is
where the flush happens: `interpret_with_console` flushes inside the collection call. With `to_buffer` it returns,
which ends the collection call. Each new `collect_mcycle_root_hashes` call then pays a fixed entry cost:
`update_hash_tree()` rehashes the always-dirty pages, and the result and dirty-page vectors are reserved again.
`collect_mcycle_bundle` cannot drain the buffer. Once the 4 KiB buffer is full, `append_output` drops the oldest
byte and writes a WARNING line to stderr, and the buffer stays full. From then on every `putchar` breaks the
collection, in any flush mode, `when_full` included.

The test asserts two things:

1. Every case collects the same hashes and reaches the same final root hash (R14, R2). This holds today.
2. For both collection paths, `CPU(to_buffer) <= 10 x CPU(to_file control)` (R12 and the High case of section 8).
   This is violated today.

## Requirement

- THREAT_MODEL R12: "Each of the following operations has a worst case in host time and memory that is bounded and
  at most linear in the cycles it executes or the bytes it covers. They are ... a part of a claim ..."
- Section 8, High: "A defect that lets the guest, or host load that the deployment was sized for, multiply the
  worst-case cost of an operation listed in R12 by a constant factor, compared with the same operation without the
  defect ... A cost that the specified semantics require is not a defect."
- R14: "Output to the host, such as console output, must not affect the state." This holds: the hashes are equal.

The `run-buffer` line shows that the semantics do not require the extra cost. It takes the same 100001
console-output breaks of the interpreter in about 0.04 s. The same breaks cost about 40 us each inside a collection.

Role: `collect_mcycle_root_hashes` is honest operator in the AUDIT.md component table. `collect_mcycle_bundle`
belongs to the rest of the machine API. The test does not establish whether a production node configures a
`to_buffer` console. That is for the reviewer.

## How to run

```sh
bugs/run.sh R1-R14-1      # about 15 s; needs docker (toolchain image) to build the guest
```

## Expected output on audit/prt2

The CPU times vary from run to run. The ratios were about 90-150x in every run.

```
roots-file     cpu=  0.0289s mcycle=106259 calls=1 stderr_warnings=0 ...
roots-buffer   cpu=  4.3239s mcycle=106259 calls=100001 stderr_warnings=0 ...
run-buffer     cpu=  0.0437s mcycle=106259 calls=100001 stderr_warnings=0 ...
bundle-file    cpu=  0.0334s mcycle=106259 calls=7 stderr_warnings=0 ...
bundle-buffer  cpu=  3.0464s mcycle=106259 calls=7 stderr_warnings=95904 ...
OK: R14/R2: collected hashes and final root hash do not depend on the console
VIOLATED: R12/section 8: collect_mcycle_root_hashes with a to_buffer console costs 149.4x the same collection with the to_file control ...; bound 10x
VIOLATED: R12/section 8: collect_mcycle_bundle with a to_buffer console costs 91.1x the same collection with the to_file control ...; bound 10x
run.sh: R1-R14-1: exit 1 (bug present)
```

The test exits 1. It would exit 0 if collecting with a `to_buffer` console cost about the same as with a flushed
console.
