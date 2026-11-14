# R1-BOUNDARY-3: crisium's seal lookup grows with the number of past epochs

Component: PRT player process, `doc/recipes/crisium.lua` (`seal_history` and `get_seal`, lines 207-220), with
`doc/recipes/prt-log-history.lua`. Role: Support (AUDIT.md); it stands in for the honest operator's chain
observation and restart.

## Requirement

THREAT_MODEL.md R12:

> The honest operator's own work outside the emulator, such as observing the chain, keeping and persisting its own
> records, and restarting, has a bounded cost per input, per yield, and per match, and its total grows only with the
> inputs, yields, and matches of the epochs still open. That total must not grow with the application's age, with the
> number of past epochs, or with chain activity that does not belong to the application.

## What the test does

`get_seal(number)` asks `seal_history` (a `prt-log-history`, never pruned) for every log of the consensus
since `getDeploymentBlockNumber()`, unfiltered, and decodes them in order (`abi:event`) until it finds
`EpochSealed(number)`. `open_epochs` calls it once for every epoch it opens. So a relaunch fetches every
consensus log since deployment, the history keeps them for the life of the process, and every new epoch
decodes all of them again. Only the previous epoch's seal is needed (`epochNumber` is an indexed topic of
`EpochSealed`).

`test.lua` loads the real `crisium.lua` (real `prt-log-history.lua`, real ABI decoding with the pinned Dave
artifacts in `bugs/harness/work/dave/patched`) in-process, with `require` stubs for the transport
(`prt-rpc`: an in-memory mock chain), the checkpoint loader and player (`prt`), the epoch listener
(`prt-epoch`), `prt-bridge.read_geometry`, `prt-dishonest` and `prt-websocket`; none of them takes part in
`get_seal`. The mock consensus holds `EpochSealed(k)` for k = 0..E-1 and `EpochStaged(k)` for k = 0..E-2.

1. **restart**: the player starts from checkpoint `epoch-E` (the honest player keeps only the newest
   checkpoints), which needs the seal of epoch E-1;
2. **new epoch**: epoch E is then sealed and checkpoint `epoch-(E+1)` appears; the player opens epoch E+1.

For each phase it counts the consensus logs `eth_getLogs` hands to the player and the logs it decodes, for
E = 2 and E = 200. It asserts that neither count grows with E (slack of 4 logs). No timing is involved.

## Run

```sh
bugs/run.sh R1-BOUNDARY-3              # E = 2 and 200
bugs/run.sh R1-BOUNDARY-3 5 2000       # other sizes
CRISIUM_LUA=/path/to/fixed/crisium.lua bugs/run.sh R1-BOUNDARY-3   # check a candidate fix
```

Runs in under a second; needs the in-tree emulator and the Dave build of the shared harness.

## Expected output on audit/prt2 (exit 1)

```
past epochs    2 (consensus logs    5): restart fetched    3 decoded    3 (1 requests) | new epoch fetched    2 decoded    5 (1 requests)
past epochs  200 (consensus logs  401): restart fetched  399 decoded  399 (1 requests) | new epoch fetched    2 decoded  401 (1 requests)
VIOLATION restart: logs fetched grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION restart: logs decoded grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION new epoch: logs decoded grow from 5 (2 past epochs) to 401 (200 past epochs)
VIOLATED: R12: crisium's seal lookup must not grow with the number of past epochs (restart and per-epoch observation cost)
run.sh: R1-BOUNDARY-3: exit 1 (bug present)
```

A copy of `crisium.lua` whose `get_seal` uses a fresh history filtered by
`abi:topics("EpochSealed", number)` gives 1 fetched / 1 decoded in both phases for both E, and the test exits 0.
The per-new-epoch fetch is already incremental (2 logs); the growth is in the restart fetch, the retained
history and the per-epoch re-decoding.
