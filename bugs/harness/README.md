# Audit harnesses (`bugs/harness/`)

Shared harnesses of the `audit/prt2` campaign (AUDIT.md, Process step 1). Scripts and small sources are tracked
here; every large, fetched or built artifact lives in `bugs/harness/work/` (gitignored) and is rebuilt by
`setup.sh`. All paths below are relative to the repository root unless absolute.

```sh
bugs/harness/setup.sh            # rebuild everything from a fresh clone (idempotent, ~40 min cold; root, docker)
bugs/harness/check-all.sh        # one PASS/FAIL/SKIP line per harness (quick checks, a few minutes)
CHECK_LONG=1 bugs/harness/check-all.sh   # also the PRT demo on the chain and the player restart runner
```

`setup.sh` installs the host packages (Ubuntu 24.04: boost 1.83, lua5.4, lua-socket/posix/lpeg/dkjson, gpp,
e2tools, libarchive, ...), starts `dockerd` if no daemon answers, and then runs every build script below.
`setup.sh --force` rebuilds docker images, the regenerated step and Dave from scratch;
`--skip-mss-tests` skips machine-solidity-step's own test targets.

## 1. Proof-of-concept runner: `bugs/run.sh`, `bugs/env.sh`

```sh
bugs/run.sh <ID> [args]      # runs bugs/<ID>/test.lua (lua5.4) or bugs/<ID>/test.sh (bash), cwd = bugs/<ID>/
```

Exit status convention:

| status | meaning |
|---|---|
| 0 | fixed: the behavior the threat model requires holds |
| 1 | bug present (the test observed the violation) |
| 2 | harness error: no test, emulator not built, missing artifact, setup error, timeout (`RUN_TIMEOUT`, default 3600 s), or any exit status other than 0 and 1 |

`bugs/env.sh` (sourced by `run.sh`; source it yourself for interactive work) sets `LUA_PATH_5_4`/`LUA_CPATH_5_4`
to the in-tree build (`src/?.so`, `src/?.lua`, `tests/lua/?.lua`, `doc/recipes/?.lua`, `bugs/harness/lib/?.lua`),
`LD_LIBRARY_PATH=src`, `PATH` (src, work/bin with `cartesi-machine`, `xgenext2fs`, foundry), and exports
`REPO HARNESS HARNESS_WORK CARTESI_IMAGES_PATH LINUX_IMAGE ROOTFS_IMAGE ROOTFS_DOCS_IMAGE HARNESS_CONFIGS
BAREMETAL_DIR RECIPES_DIR CARTESI_MACHINE` (= `lua5.4 src/cartesi-machine.lua`). With `HARNESS_SANITIZE=1` it
switches to the ASan+UBSan build (section 7).

An uncaught Lua error makes `lua5.4` exit 1, which the runner cannot tell from "bug present". So wrap the test in
`harness.main`, which maps a returned `true` to 0, `false` to 1 and any error to 2:

```lua
local harness = require("harness")          -- bugs/harness/lib/harness.lua
harness.main(function()
    local cartesi = require("cartesi")
    local m <close> = harness.machine(harness.config_dir("valid-template") .. "/machine")  -- error -> exit 2
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, harness.encode_advance({ payload = "x" }),
        m:get_root_hash())
    ...
    return harness.expect(observed == required, "R5: delivery ... must ...")   -- true -> 0, false -> 1
end)
```

Helpers in `harness.lua`: `hex/unhex`, `bug(msg)` (exit 1), `setup_error(msg)` (exit 2), `expect`, `read_file`,
`config(name)`/`config_dir(name)`, `machine(cfg_or_dir)`, `baremetal(name)` (path of a built guest),
`encode_advance{chain_id, app_contract, msg_sender, block_number, block_timestamp, prev_randao, index, payload}`
(ABI EvmAdvance, as libcmt/`rollup` decode it), `sh(cmd)`. A shell test should `exit 2` on setup failures itself.
`bugs/harness/selftest/run-selftest.sh` checks the convention (0/1/2 mapping).

## 2. Emulator and guest images

| what | script | artifacts |
|---|---|---|
| toolchain image `cartesi/machine-emulator:toolchain` (this branch's Dockerfile, stage `toolchain`) | `docker/build-images.sh toolchain` | docker image |
| in-tree `make` (builds the uarch with `make uarch-with-toolchain` in that image) | `emulator/build.sh` | `src/*.so`, `src/cartesi-jsonrpc-machine`, `uarch/uarch-pristine-*.c`, `work/bin/` command links |
| images of `dependencies.lock`, sha256-verified: `linux.bin` (cartesi/linux v6.18.56-ctsi-1), `rootfs.ext2` (= machine-guest-tools v0.18.1-test1 `rootfs-tools.ext2`), guest-tools `.deb`/`.tar.gz`; `git lfs pull` of `doc/recipes/rootfs-docs.ext2` + `make -C doc check-rootfs-docs` | `emulator/fetch-images.sh` | `work/images/`, `work/downloads/` |
| `xgenext2fs` (cartesi/genext2fs v1.5.6, as doc/Dockerfile) | `emulator/build-xgenext2fs.sh` | `work/bin/xgenext2fs` |
| emulator runtime image `cartesi/machine-emulator:devel` (final stage of the Dockerfile, = `make build-emulator-image`) | `docker/build-images.sh emulator` | docker image |

Smoke: `emulator/smoke.sh` (Linux boot with the guest-tools rootfs, Lua module, jsonrpc server).

`docker/build-images.sh` never edits the Dockerfile: it writes a copy to `work/docker/Dockerfile` that adds one
line at the top of the `toolchain` stage, copying the session's HTTPS-proxy CA (if any) into
`/usr/local/share/ca-certificates` so the stage's https fetches (stylua, luarocks) work behind the proxy, names
the final stage `runtime`, and appends a `uarch-rebuild` stage. The build context is the files git tracks (from
the working tree) minus `bugs/`, `doc/` and generated files (a Dockerfile-specific `.dockerignore`), so images
never pick up in-tree build outputs.

Submodule note: `third-party/riscv-tests` has a relative URL that resolves against the fork remote
(`edubart/riscv-tests`, which does not exist); the scripts set `submodule.tests/riscv-tests.url` to
`https://github.com/cartesi/riscv-tests.git` (commit a64ad67 is there) in `.git/config`.

## 3. machine-solidity-step regenerated, and the EVM harness

`solidity-step/regenerate.sh [--force] [--no-tests]`:

* `work/solidity-step/released`: v0.17.0-test1 at commit 6f91eb9b, untouched (the released generated code).
* `work/solidity-step/regenerated`: the project's `generate-step generate-reset generate-send-cmio-response
  generate-constants` against this branch (`EMULATOR_DIR` shim: `src` -> this repo's `src/`; the constants come
  from `cartesi/machine-emulator:devel` built from this branch, as the project does, and are cross-checked
  against the in-tree Lua module), then `generate-prod generate-replay`. Replay tests use test data
  **regenerated from this branch**: `tests/uarch` built with the pinned toolchain (`make -C tests uarch` in the
  toolchain image) and `tests/lua/uarch-riscv-tests.lua json-step-logs --create-reset-uarch-log
  --create-send-cmio-response-log` with the in-tree emulator (59 logs).
* If the pure regeneration does not compile, `work/solidity-step/regenerated-patched` gets the minimal,
  labelled harness workaround(s) in `solidity-step/patches/` and is built and tested instead.
  `work/solidity-step/step` points at the variant that builds (used by the EVM harness and by Dave).
* Outputs: `build-status.txt`, `results.txt` (test-mock / test-replay / test-prod), `failures.txt`,
  `diff-summary.txt` and `diff.patch` (released vs regenerated generated files; also released vs regenerated
  replay logs and test binaries), `test-*.log`.

**State on audit/prt2 (0e27bc6)**: see `work/solidity-step/{build-status,results,diff-summary}.txt`. At the time of
writing: the pure regeneration does NOT compile (`UArchStep.sol`: `Undeclared identifier TLB_NUM_SETS`: the
write-TLB ecall of `src/uarch-step.cpp` now checks `set_index >= TLB_NUM_SETS`, which neither the template nor
`generate_EmulatorConstants.lua` defines, so the translator leaves it unqualified). Workaround
`patches/01-tlb-num-sets.sh` adds `uint64 constant TLB_NUM_SETS = 3;` (value of `cartesi.TLB_NUM_SETS`) to the
constants template. With it: test-replay 56/56 pass; test-prod 14/15 (`testCmMarchId` expects 22, regenerated
23); test-mock 3/5 (`testHaltEcallReachesCycleLimit`, `testStepEarlyReturn` expect overflow to take precedence
over halt, which this branch's uarch-step.cpp reversed). Pure regenerated diff vs released: `EmulatorConstants.sol`
(CM_MARCHID 22 -> 23, UARCH_PRISTINE_STATE_HASH 0x558f...3926 -> 0x89ae...43d7) and `UArchStep.sol` (TLB index
check, halt/overflow precedence); `UArchReset.sol` and `SendCmioResponse.sol` unchanged.

**EVM harness** (`solidity-step/evm/`): `start.sh` starts a dedicated anvil (port `EVM_STEP_PORT`, default 8546,
`--code-size-limit 4000000 --disable-block-gas-limit`: harness settings) and deploys `src/StepVerifier.sol`, a
contract with external entry points over the regenerated libraries: `step`, `reset`, `stepThenReset`,
`sendCmioResponse`, `sendCmioResponseThenStep`, `metaStep`, `constants`. Each reverts unless the proof is fully
consumed. `stop.sh` stops it. Lua client `bugs/harness/lib/evm_step.lua`:

```lua
local evm = require("evm_step")
local e = evm.connect()                                   -- work/evm/{rpc-url,address}
local ok, root, status = e:step(m:get_root_hash(), m:log_step_uarch())   -- ok=false, root=revert message
e:step_then_reset(root, step_log, reset_log); e:meta_step(root, counter, step_log, reset_log)
e:send_cmio_response(root, reason, data, revert_root, log); e:send_cmio_response_then_step(root, data, slog, stlog)
evm.encode_log(log), evm.concat_logs(...), evm.data_hash(data), evm.abi_encode(sig, args), e:call(calldata)
```

Proofs use the encoding of `doc/recipes/prt-ethereum.lua` (`append_log`), the one Dave's
`CartesiStateTransition` consumes. Tests may also tamper with the log tables before calling. Smoke:
`solidity-step/evm/smoke.lua` (20 uarch steps of a Linux boot, step+reset, delivery+step on a valid template,
metaStep, tampered log rejected, marchid/pristine constants equal to the emulator's).

## 4. Independent uarch rebuild

`uarch-rebuild/rebuild.sh`: Docker stage `uarch-rebuild` (on the `toolchain` stage: debian:trixie-20250811,
gcc-riscv64-unknown-elf=14.2.0+19, g++-14-riscv64-linux-gnu=14.2.0-19cross1; binutils-riscv64-unknown-elf
2.44-3+7+b1 is NOT pinned by the Dockerfile) compiles a fresh copy of the tracked sources. It compares:
(r) the rebuilt `compute-uarch-pristine-hash` output and the emulator's own hash-tree node over the rebuilt
`uarch-ram.bin` (`node-hash.lua`), (a) the in-tree `uarch/uarch-pristine-hash.c` and
`cartesi.UARCH_PRISTINE_STATE_HASH`, (b) `UARCH_PRISTINE_STATE_HASH` of the regenerated `EmulatorConstants.sol`,
and the sha256 of both `uarch-ram.bin`. Report: `work/uarch-rebuild/report.txt`. Exit 0 iff all agree. On
0e27bc6 all agree: `0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7`, uarch-ram.bin sha256
`e77676456ce3f53f4792db714da93bfe6d0bbf5c499fee08e4d1e19757d8eb54`. `FORCE=1` rebuilds the image.

## 5. Local chain with the pinned Dave contracts

`chain/build-dave.sh [patched] [released]`: Dave v3.0.0-alpha.7 (commit 7eb6c6be) built on the host as
`doc/Dockerfile.prt` does, with `machine/step/src` replaced by `work/solidity-step/step/src` (Dave itself pins
machine/step at fb00a32c, not the v0.17.0-test1 tag), soldeer deps (OpenZeppelin 5.5.0, forge-std 1.9.6,
cartesi-rollups-contracts 3.0.0-alpha.10 with its recursive deps), forge 1.5.1, solc 0.8.30:

* `work/dave/patched`: with `doc/recipes/prt-contracts.patch` (recipe geometry), for the PRT recipes;
* `work/dave/released`: released constants, for tests of the contracts themselves (audit these).

Chain scripts (anvil with the parameters of `prt-demo.sh run_anvil`):

```sh
bugs/harness/chain/start-chain.sh                 # anvil on 127.0.0.1:${CHAIN_PORT:-8547}; stop-chain.sh
bugs/harness/chain/deploy.sh patched|released [template-hash]  # prt-deploy.lua; work/chain/deploy-<v>/deployment.json
bugs/harness/chain/smoke.sh released|patched-stf  # deploy + CartesiStateTransition.transitionState vs the emulator
bugs/harness/chain/smoke.sh patched               # ... + the PRT demo in smoke mode
bugs/harness/chain/prt-demo.sh [smoke|story|transactions|proofs]   # doc/recipes/prt-demo.sh on the host
bugs/harness/chain/test-dave.sh [released|patched]   # Dave's own suites: prt-contracts::test-disputes, rollups-contracts::test
bugs/harness/chain/reflink-fs.sh                  # XFS (reflink) loop mount at work/prt-runs, done by prt-demo.sh
. bugs/env.sh; . bugs/harness/chain/env.sh        # recipe environment (PRT_DAVE_DIR, CARTESI_IMAGES_PATH, ...)
```

`chain/env.sh` reproduces `doc/Makefile HOST=yes`: default images = `linux.bin` + `rootfs-docs.ext2`
(`work/images-docs/`), `RECIPES_DIR=doc/recipes`, `PRT_DAVE_DIR=work/dave/$PRT_VARIANT`,
`PRT_OUTPUT_DIR=work/prt-runs`. `prt-demo.sh` (the recipe) starts its own anvil on 8545 unless `PRT_RPC_URL` is
set, runs the bridge unit test, builds the calculator fixture in `doc/recipes/cache/game-tests` (gitignored),
deploys and runs the players. Run artifacts: `work/prt-runs/run.XXXXXX/`.
`chain/smoke-stf.lua <deployment.json>` checks transitions through a deployed CartesiStateTransition.

Disk: the players clone stored machines for every epoch entry, which `doc/Makefile` expects to be reflinks. On the
container's ext4 a smoke run took 6.2 GB and the story ran out of disk, so `prt-demo.sh` and
`player-restart/run.sh` first loop-mount a sparse XFS image with `reflink=1` (`work/prt-fs.img`, apparent 60 GB)
at `work/prt-runs` (`chain/reflink-fs.sh`, root). The mount does not survive a container restart; the scripts
remount it. Delete old `work/prt-runs/run.*` directories between runs.

## 6. Player stop/restart runner

`player-restart/run.sh fixed` runs the story with the recipe's `PRT_TEST_RESTART=yes` (the honest player is
`kill -9`ed after an input, after the seal, during a bisection, after a uarch claim, before staging, after a
removal). `player-restart/run.sh random [smoke|story]` runs an OUT-OF-TREE COPY of `prt-demo.lua`
(`work/player-restart/recipe-copy/`) with a hook that, at the start of each orchestration wait, kills the honest
player with probability `RESTART_PROBABILITY` (0.15) at most `RESTART_COUNT` (3) times, seeded by `RESTART_SEED`
(printed). `prt-supervise.sh` relaunches it from `players/honest/` (its stored state); the demo's own assertions
check that it settles. Exit 0 if it settles after at least one kill, 1 if it fails after kills, 2 otherwise.
Logs: `work/player-restart/`.

## 7. Bare-metal guests, ready machine configurations, sanitizer build

**Bare-metal builder** `baremetal/build.sh` (`-o out.bin src.c|src.S ...`, or no arguments for all examples into
`work/baremetal/`): pinned `riscv64-unknown-elf-gcc` of the toolchain image (or `BAREMETAL_CC=host`),
`-march=rv64imac_zicsr_zifencei -mabi=lp64`, include paths `baremetal/include` and the emulator's `src/` (audited
`htif-defines.h`, `address-range-defines.h`, ...). Raw binary loaded at 0x80000000 (machine starts there in
M-mode). Unless a source defines `_start`, `lib/crt0.S` (stack, bss, `main`, halt with its return value) and
`lib/runtime.c` are linked. API (`include/cm-baremetal.h`): `cm_halt`, `cm_putchar/puts`, `cm_yield_manual/
automatic`, rx/tx buffer macros, `cm_keccak256`, an outputs Merkle tree of height 63 (`cm_outputs_*`, same
convention as `cartesi.hash-tree` frontiers), `cm_rollup_accept(root)`, `cm_rollup_reject()`,
`cm_rollup_emit_output/report()`, `cm_rollup_exception()`. Examples: `halt.c` (exit 42), `accept.c` (accepts
every request with the empty root), `reject.c`, `emit-output.c` (emits each advance request as an output and a
report, accepts with the updated root; payload `R` rejects, `H` halts(7), `E` throws), `accept-asm.S` (pure
assembly). Smoke: `baremetal/smoke.lua`. Use from a test: `harness.baremetal("emit-output")`, or build your own
in `bugs/<ID>/`: `$HARNESS/baremetal/build.sh -o guest.bin guest.c`. RAM length must be at least 4 MiB (64 MiB in
the configs); `emit-output.c` has a 2 MiB bss buffer.

**Configurations** `configs/make-configs.sh [--force]` -> `work/configs/<name>/` (`config.lua`, `machine/`
stored, `root-hash.txt`):

| name | content |
|---|---|
| `baremetal-minimal` | 64 MiB RAM = `accept.bin`; stored at mcycle 0 |
| `baremetal-template` | `emit-output.bin`, stored at its first manual yield (rx-accepted, empty outputs root) |
| `linux-rootfs` | `linux.bin` + guest-tools `rootfs.ext2` (CLI defaults); stored at mcycle 0 |
| `valid-template` | Linux + guest-tools rootfs running an echo app (`app.sh`: notice + report of each payload, payload `reject` is rejected), made with `cartesi-machine --assert-rolling-template --final-hash --store` |
| `valid-template-calc` | the doc/recipes rolling calculator (`game-test-fixtures.sh`) on the guest-tools rootfs, with `input-*.bin` |

Load with `cartesi.machine(dir .. "/machine", {})`; the Linux template takes ABI-encoded inputs
(`harness.encode_advance`). Smoke: `configs/smoke.lua`.

**Sanitizer build** `sanitizer/build.sh`: tracked sources copied to `work/sanitizer/`, `make -C src sanitize=yes`
(ASan+UBSan, `-fno-sanitize-recover=all`, `_FORTIFY_SOURCE=3`, `_GLIBCXX_ASSERTIONS`): libcartesi, `cartesi.so`,
`cartesi/jsonrpc.so`, `cartesi-jsonrpc-machine`. Use: `HARNESS_SANITIZE=1 bugs/run.sh <ID>` or
`HARNESS_SANITIZE=1 . bugs/env.sh` (or `. bugs/harness/sanitizer/env.sh`), then `san_lua test.lua` (preloads
libasan; `$LUA_SAN`, `$CARTESI_MACHINE` likewise). Any report aborts the process: a test that wants to detect
one should run the operation in a child (`harness.sh`) and look for `ERROR: AddressSanitizer` / `runtime
error:` in its stderr. Smoke: `sanitizer/smoke.sh`.

## State verified on audit/prt2 0e27bc6 (2026-11-14)

* `check-all.sh` with `CHECK_LONG=1`: all 13 lines PASS (about 2 minutes once everything is built).
* Runner: `selftest/run-selftest.sh` 0/1/2 mapping, and the sanitizer module path, OK.
* uarch pristine hash, all equal: `0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7`.
* machine-solidity-step: pure regeneration does not compile (TLB_NUM_SETS); patched variant builds; test-replay
  56/56, test-prod 14/15, test-mock 3/5 (details in section 3).
* Dave released build, Dave's own suites (`chain/test-dave.sh released`): prt-contracts::test-disputes 427/447
  (20 fail: recorded witnesses/fixtures whose roots come from the previous step, e.g. "Read word root doesn't
  match", and `testCmMarchIdIsTheStepConstant` 23 != 22), rollups-contracts::test 17/19. List:
  `work/dave/test-released-failures.txt`.
* Both Dave builds deploy (`prt-deploy.lua`, which also checks the on-chain UARCH_PRISTINE_STATE_HASH against the
  emulator) and their CartesiStateTransition verifies emulator transitions (`chain/smoke-stf.lua`).
* PRT demo on the patched build: `smoke` settles epochs 0, 1, 2 (honest + sentinel, ~1.5 min); `story` with
  `PRT_TEST_RESTART=yes` (honest player, 7 adversaries and a sentinel; 6 kills of the honest player) settles both calculator epochs; anvil
  peaks near 6 GB RSS in the story.
* Random restarts (`player-restart/run.sh random smoke`, seed 42): 3 kills, 3 relaunches, settles.

## Known limitations

* Docker is required for the toolchain (uarch, bare-metal guests, test binaries) and for `generate-constants`.
  `dockerd` is started by the scripts when root. Inside containers only plain HTTP and the proxy (with
  `--network host`) reach the network.
* The proxy CA line in the generated Dockerfile is the only change to the image recipe; apt.llvm.org (clang-tidy
  22) and Debian package versions other than the two pinned compilers float with the archives.
* `regenerated-patched` is a labelled workaround, not the released or pure-regenerated step; Dave and the EVM
  harness use it only because the pure regeneration does not compile.
* `StepVerifier` is a harness wrapper (not a deployed contract): use the Dave build's `CartesiStateTransition`
  (chain/) for referee-model behavior (input witness, counters).
* The EVM harness anvil disables code-size and block gas limits; gas measurements need the real limits.
* The loader prints `Relink .../cartesi.so with .../cartesi/filesystem.so for IFUNC symbol ...` when the recipes
  load `cartesi.filesystem`; it is a warning of the in-tree build and does not stop anything.
* `random` restarts use an out-of-tree copy of `prt-demo.lua` (hook marked `[audit harness]`); `fixed` uses the
  recipe unchanged.
* `doc/recipes/prt-demo.sh` starts anvil with `run_anvil ... &` and its exit trap kills that background subshell,
  not anvil: on the host the anvil on 8545 survives the demo (and a later demo silently reuses it, which once
  ended in an OOM kill of anvil at ~13 GB). `chain/prt-demo.sh` and `player-restart/run.sh` refuse to start if
  8545 answers, and kill the recipe's anvil at exit.
* Stored machine directories are large (Linux configs ~400 MB each); the whole `work/` is ~8 GB plus ~5 GB of
  docker images; Dave and solidity-step builds compile with via-IR and take ~15 minutes each.

## Disk note: anvil state dumps

`anvil-wrap.sh` (run by `setup.sh`) wraps `work/foundry/bin/anvil` so that it passes `--max-persisted-states 16` unless the
caller sets `--max-persisted-states` or `--prune-history`. Plain anvil dumps every block state under
`~/.foundry/anvil/tmp` and filled the disk during round 1. Tests that query state at old blocks must raise the bound
with `ANVIL_MAX_PERSISTED_STATES`. Always stop the anvil you start; stale dumps can be removed from that directory.
