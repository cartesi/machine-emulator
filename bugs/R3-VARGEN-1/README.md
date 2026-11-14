# R3-VARGEN-1: the emulator build links stale generated uarch files

## What is asserted

The uarch program is generated from the interpreter sources (`src/interpret.cpp` and its headers, `uarch/*`) into
`uarch/uarch-ram.bin` and embedded in the emulator through two untracked generated files,
`uarch/uarch-pristine-ram.c` and `uarch/uarch-pristine-hash.c`. `src/Makefile` runs the uarch build only
`ifeq (,$(wildcard ../uarch/uarch-pristine-hash.c))` (target `generate-uarch-pristine`), so once these files exist
they are never refreshed, whatever changed in the sources.

`test.sh` copies the tracked `src`, `uarch`, `tools` and `Makefile` of this working tree into a temp dir and:

1. Control: without generated files, `make -n -C src libcartesi.a` plans the uarch build
   (`make -C .. uarch` / `uarch-with-toolchain`). This checks the detector; failure here is exit 2.
2. Stale case: plants generated uarch files dated 2020-01-01 (older than every uarch source, as an earlier build
   leaves them after a pull, checkout or interpreter edit). The test requires that the build either rebuilds the
   uarch from the current sources or refuses. On `audit/prt2` the plan instead compiles the new `interpret.cpp`
   and the stale `uarch-pristine-*.c`, and archives them together into `libcartesi.a`, without any error.
3. Evidence only (when the bug shows): the two stale objects are really compiled with the emulator's Makefile and
   linked into a tiny probe, which prints the embedded pristine hash: the planted stale value.

Requirement (THREAT_MODEL.md, R13): "The uarch program, its pristine hash, and the verifier code that a deployment
fixes on-chain must be reproducibly buildable from audited source." Also A6 ("Every verifier, the uarch program fixed
on-chain, and every honest operator in a deployment implements the same state transition function") and R2 (native
interpretation and the uarch must agree), which a build that mixes a new native interpreter with an old uarch breaks.

Not asserted, noted: the repository `.dockerignore` sends `uarch/uarch-pristine-*.c` and (by an explicit exception)
`uarch/uarch-ram.bin` into the Docker context, and the Dockerfile's `COPY . . ; make` runs the same
`src/Makefile` rule, so the image (and machine-solidity-step's `generate-constants`, which reads
`UARCH_PRISTINE_STATE_HASH` and `CM_MARCHID` from that image) inherits the same staleness. A fix of the Makefile
rule covers that path too, so the test does not require a particular `.dockerignore`.

A fix was simulated (making `generate-uarch-pristine` also rebuild when any uarch source is newer than
`uarch-pristine-hash.c`): the test then exits 0.

## How to run

```sh
bugs/run.sh R3-VARGEN-1
```

Needs git, make, gcc and tar; no docker, no network, a few seconds.

## Expected output on audit/prt2 (exit 1)

```
control: tree without generated uarch files -> the plan builds the uarch:
    	make -C .. uarch coverage=no; \
    	make -C .. uarch-with-toolchain coverage=no; \
    make toolchain-exec CONTAINER_COMMAND="make uarch coverage=no"
stale: generated uarch files dated 2020-01-01, src/interpret.cpp dated <today>
stale: the plan of 'make -C src libcartesi.a' never builds the uarch; it does:
    compile interpret.cpp -> interpret.o
    compile ../uarch/uarch-pristine-hash.c -> uarch-pristine-hash.o
    compile ../uarch/uarch-pristine-ram.c -> uarch-pristine-ram.o
    archive both stale uarch-pristine objects into libcartesi.a with the new interpret.o
built objects: embedded uarch pristine hash 0x5a5a...5a, uarch image length 4 bytes
    = the planted stale hash, not one built from the current uarch sources
FAIL (R13): the build embeds a uarch program and pristine hash that are not built from the audited sources
            it compiles; it neither rebuilds them nor refuses (src/Makefile generate-uarch-pristine)
run.sh: R3-VARGEN-1: exit 1 (bug present)
```
