# R1-R1-1: uarch build depends on unpinned toolchain packages (DOES NOT REPRODUCE)

**Claim.** The Dockerfile's `toolchain` stage pins only `gcc-riscv64-unknown-elf=14.2.0+19` and
`g++-14-riscv64-linux-gnu=14.2.0-19cross1`. `binutils-riscv64-unknown-elf`, `libc6-dev-riscv64-cross`,
`linux-libc-dev-riscv64-cross` and `libstdc++-14-dev-riscv64-cross` float with the live Debian archive, and the base
image is pinned by tag. The claim is that archive drift could change `uarch-ram.bin`, and with it the pristine uarch
hash and every canonical hash, so the uarch would not be reproducibly buildable.

**Requirement (R13).** "The uarch program, its pristine hash, and the verifier code that a deployment fixes on-chain
must be reproducibly buildable from audited source."

**What the test asserts.** `test.sh` builds the uarch from `git archive HEAD` with the uarch Makefile, in ephemeral
`docker run --rm --network none` containers of `cartesi/machine-emulator:toolchain`, the image of the Dockerfile's
`toolchain` stage. It runs one control build. It then runs one build per alternate Debian build of an unpinned
package. Each alternate is listed in `alternates.txt`, fetched from snapshot.debian.org and checked by sha1, and it
replaces only that one package. The alternates are:

* binutils 2.43.1-5+7 (the earlier trixie build) and binutils 2.45.50.20251125-1+7+b2. The next binutils, 2.46,
  declares Breaks on the pinned gcc 14.2.0, so apt could not install it.
* libc6-dev 2.40 and libc6-dev 2.42.
* linux-libc-dev 7.2.
* libstdc++-14-dev 14.3.0.

Every build must give the same results as the in-tree build:

* `uarch-pristine-hash.c` equals `cartesi.UARCH_PRISTINE_STATE_HASH`, and equals the regenerated
  `EmulatorConstants.sol` constant when the harness has built it.
* The sha256 of `uarch-ram.bin` equals that of the in-tree `uarch/uarch-ram.bin`.

The test exits 1 if any build differs and 2 on a setup error: docker or the image is missing, a download fails, or a
build fails.

**Run.** `bugs/run.sh R1-R1-1`. It takes about 3.5 minutes. It needs docker, the harness toolchain image, and HTTPS
access to snapshot.debian.org.

**Observed on audit/prt2 (exit 0, twice).** All seven builds give
`0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7` and `uarch-ram.bin` sha256 `e77676456ce3...`.
That matches the emulator and the regenerated step. The linker reported in each line confirms that the swapped
binutils was the one used. The live trixie archive (checked 2026-11-14) still serves the versions in the image:
binutils 2.44-3+7+b1, gcc 14.2.0+19, g++ 14.2.0-19cross1, libc6-dev 2.41-11cross1 and linux-libc-dev 6.12.38-1cross1.

**Conclusion.** The uarch program reproduces from audited source today. It also reproduces byte-for-byte across
every tested drift of the packages the Dockerfile leaves unpinned. The candidate's state, an unpinned toolchain
package that changes the uarch bytes, could not be produced. The missing digest pin on the base image and the missing
committed expected pristine hash are hardening gaps. This test shows no violation of R13 from them.
