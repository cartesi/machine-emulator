# R1-O1-3: the PRT player adopts the template from a root read from its cached hash-tree data

## What is asserted

`prt.store_first_epoch_checkpoint` (doc/recipes/prt.lua) is how the PRT player adopts the application's template:
`prt-demo.lua` calls it before launching the players (and once more per sentinel), and `crisium.lua` then asserts
that the epoch-0 checkpoint's `final_state_hash` equals the application's on-chain template hash. The function
clones the template directory and loads the clone with `cartesi.machine(temporary_directory)`, without
`{ clear_hash_tree = true }`; it checks the rolling-template conditions (including the pristine-uarch node via
`get_node_hash`) on that cached tree and writes `machine:get_root_hash()` as `initial_state_hash` and
`final_state_hash` of `epoch.json`. The rebuild happens only later, in `new_stored_player`.

The test:

1. stores the harness `baremetal-template` machine (a valid template, content hash `0x428a6bb8...ac75` =
   `root-hash.txt`) with its cached hash-tree data, in a temp dir;
2. control: on an untouched copy, `store_first_epoch_checkpoint` records the content hash (otherwise exit 2);
3. makes only the cached data stale: overwrites one node of the RAM `.dht` (offset 96) and marks the RAM `.dpt`
   clean. No `.bin` file and no `config.json` changes; control: loading with `clear_hash_tree` still yields the
   content hash (otherwise exit 2);
4. calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(10), out)` and `prt.load_epoch_checkpoint`,
   and requires that the recorded `initial_state_hash` and `final_state_hash` equal the content hash. A refusal
   (error) of the valid template also counts as the violation.

A fix (loading the clone with `{ clear_hash_tree = true }` in `store_first_epoch_checkpoint`) makes the test exit 0;
this was checked with an out-of-tree patched copy of `prt.lua` placed first on `LUA_PATH_5_4`.

## Requirement

THREAT_MODEL.md, O1: "An operator who adopts a stored machine it did not produce rebuilds the cached hash-tree
data from the contents when loading it, and only then compares the root hash with the on-chain commitment."
Section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must follow
them". Section 2, valid template: "For a stored machine, 'recomputed from its contents alone' means after
rebuilding its cached hash-tree data (O1). A root hash read from a machine loaded without that rebuild does not
check this condition." Honest operator's path: "Obtaining its valid template. For a template the operator did not
produce, this includes rebuilding its cached hash-tree data (O1)."

## How to run

```sh
bugs/run.sh R1-O1-3      # needs the in-tree build and bugs/harness/work/configs/baremetal-template; ~3 s
```

## Expected output on audit/prt2

```
control: untouched template, epoch-0 checkpoint records 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (rebuilt with clear_hash_tree): 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
root read from the stale cached data (no rebuild):    0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint initial_state_hash: 0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint final_state_hash:   0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint machine rebuilt:    0x428a6bb8...ac75 (differs from the manifest: new_stored_player would abort too)
VIOLATED: O1: adopting a stored machine rebuilds the cached hash-tree data, and only then compares/records the root hash ...
run.sh: R1-O1-3: exit 1 (bug present)
```

Because the checkpoint directory then exists, a relaunch returns early from `store_first_epoch_checkpoint` and keeps
the wrong hash, so crisium's "epoch 0's checkpoint is not the template" assertion fails on every start.
