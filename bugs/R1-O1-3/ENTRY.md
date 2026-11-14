## R1-O1-3

**Title.** The PRT player adopts the template without rebuilding its cached hash-tree data. `prt.store_first_epoch_checkpoint` records a root read from that cache, crisium compares it with the on-chain template hash, and a valid template whose cache is stale is refused on every start.

**Severity.** Medium

### Problem

`prt.store_first_epoch_checkpoint` is how the PRT player adopts the application's template. `prt-demo.lua` calls it before it launches the players, and once more for each sentinel. The function clones the template directory and loads the clone with `cartesi.machine(temporary_directory)`, which does not pass `{ clear_hash_tree = true }`. On the tree loaded from the cache, it runs `assert_rolling_template`, whose pristine-uarch check calls `get_node_hash`. It then writes `machine:get_root_hash()` into `epoch.json` as `initial_state_hash` and `final_state_hash`. The root it writes therefore comes from the cached hash-tree data, not from the contents.

Next, `crisium.lua` asserts that this `final_state_hash` equals the application's on-chain template hash ("epoch 0's checkpoint is not the template"). That is a comparison with the on-chain commitment made before any rebuild, which O1 forbids. The rebuild happens only later, in `new_stored_player`.

Take a valid template that someone else distributed and whose cached data does not match its contents. The player records a wrong hash for it and refuses to defend it. The checkpoint directory then exists, so on a relaunch `store_first_epoch_checkpoint` returns early, keeps the wrong hash, and the refusal repeats on every start.

In the role the player stands in for, this is a completeness failure: the honest operator cannot obtain its valid template, so it cannot respond, and a dishonest claim can win by default. The reverse case only fails later. If the cache matches the on-chain hash but the contents do not, crisium passes and `new_stored_player`'s rebuild then aborts. So the defect is a stall, not the adoption of a wrong state.

### Component, role and area

The component is the PRT player in `doc/recipes`. AUDIT.md lists it as "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs the player". The area is template adoption and the epoch-0 checkpoint.

### Location

- `doc/recipes/prt.lua`, `store_first_epoch_checkpoint`, lines 2743-2776. The load without a rebuild is at line 2757: `cartesi.machine(temporary_directory)`. The function also calls `assert_rolling_template` (lines 956-969) and records `template_hash = machine:get_root_hash()`.
- `doc/recipes/crisium.lua:236`: `assert(manifest.final_state_hash:lower() == template_hash, "epoch 0's checkpoint is not the template")`.
- `doc/recipes/prt-demo.lua:76` and `:131` call the function. `doc/recipes/prt.lua` `new_stored_player`, lines 3206-3218, is the only place where the template is rebuilt.

### Evidence and test

`bugs/R1-O1-3/` contains `test.lua` and `README.md`. Run the test with `bugs/run.sh R1-O1-3`. It takes about 3 s and needs the in-tree build and `bugs/harness/work/configs/baremetal-template`. It does the following:

1. It stores the harness `baremetal-template`, a valid template whose content hash is `0x428a6bb8...ac75`, together with its cached hash-tree data.
2. Control: on an untouched copy, `store_first_epoch_checkpoint` records the content hash.
3. It makes only the cached data stale. It overwrites 32 bytes at offset 96 of the RAM `.dht` and marks the RAM `.dpt` clean. No `.bin` file and no `config.json` changes. Control: loading with `clear_hash_tree` still gives `0x428a...ac75`.
4. It calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(10), out)` and requires that the recorded hashes equal the content hash.

On audit/prt2 it prints the following. The reviewer re-ran it twice and got the same output and exit 1 both times:

```
control: untouched template, epoch-0 checkpoint records 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (rebuilt with clear_hash_tree): 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
root read from the stale cached data (no rebuild):    0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint initial_state_hash: 0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint final_state_hash:   0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint machine rebuilt:    0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75 (differs from the manifest: new_stored_player would abort too)
VIOLATED: O1: adopting a stored machine rebuilds the cached hash-tree data, and only then compares/records the root hash (...)
run.sh: R1-O1-3: exit 1 (bug present)
```

The reviewer then tested the fix. It placed an out-of-tree copy of `prt.lua` first on `LUA_PATH_5_4`, with `{ clear_hash_tree = true }` added to that one load. The test then printed `0x428a...ac75` for both recorded hashes and "(matches the manifest)", and exited 0. Opus 5.5 found, proved and reviewed the issue, with no fallback.

### Trigger and reachability

Anyone who distributes the template directory can trigger this. They hand the operator a valid template whose cached hash-tree data does not match its contents: a stale, corrupted or deliberately altered `.dht`/`.dpt`, or a dirty-page record that is wrongly clean. The manual says the stored template "is the artifact distributed to anyone who wants to run the application in their own Cartesi Node", and it tells operators to load a directory they did not produce with `--clear-hash-tree` "before trusting its state hash".

Such a directory is still a valid template. Its contents, and the content hash rebuilt from them, are unchanged. THREAT_MODEL section 4 says: "A snapshot's cached hash-tree data is not part of any valid-template condition". No machine state has to be reached, because the trigger is the directory the operator adopts.

### Rating

1. **Out of scope: no, under the reading judged best supported.** The exclusion checked is "Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its adoption without a rebuild (O1)." Here the cache survives because the shipped tool itself skips the rebuild. Section 5 makes that the tool's defect: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must follow them". That clause covers this component, a reference player shipped in `doc/recipes`. The snapshot exclusion ("loading a snapshot ... that does not meet the conditions of a valid template") does not apply, because the template is valid.
2. **Role: Support.** AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support." Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an operator". The player is an implementation of an operator. No honest-operator component shares the defect: the emulator's `clear_hash_tree` rebuild works, as the test's control shows.
3. **High and Medium cases: Medium.** "A defect that only a support component shows, when section 3 rates it Medium." The stood-in role's rating, given in step 4, is Critical. No High or Medium case fits it in the honest-operator role, since it is not a case about unreachable states or data the operator may decline.
4. **Critical in the stood-in role.** Section 2, honest operator's path: "Obtaining its valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data (O1)." O1: "rebuilds the cached hash-tree data from the contents when loading it, and only then compares the root hash with the on-chain commitment." Section 1, completeness failure: the honest operator "cannot respond in time". Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is critical." That is Critical in the honest-operator role, so Medium for the support player.

There is a second reading. It applies the section 8 exclusion "need the cached hash-tree data ... to survive its adoption without a rebuild (O1)" literally, to any component, and then the issue is Out of scope. The facts that decide between the readings are textual. The exclusion would have to cover the case where the shipped tool's own adoption skips the rebuild. Section 5 says those tools "must follow" O1, and that a defect that "defeats the rebuild itself" is not excused. That supports the first reading.

### Possible solution and risks

In `store_first_epoch_checkpoint`, load the clone with `cartesi.machine(temporary_directory, { clear_hash_tree = true })` before `assert_rolling_template` and `get_root_hash`. Optionally, compare the result with the on-chain template hash there. The rebuild costs one full hash of the template at adoption, which `new_stored_player` already pays. It does not rewrite the stale cache in the checkpoint directory. Later loads of that directory rebuild (`new_stored_player`) or come from the operator's own process, so this is harmless. Alternatively, rebuild in the clone with sharing so that the stored cache is refreshed too.

Checkpoints written before the fix keep the wrong hash, because the function returns early when the directory exists. Operators must delete `checkpoints/epoch-0` once.

### Risk of not fixing it

An operator who runs the reference player on a template it did not produce, and whose cached data is stale or was altered by the distributor, never defends epoch 0. Until someone notices and rebuilds the template by hand, a dishonest claim can win by default. Because the player is support, no production deployment is exposed directly. The risk is that the reference implementation teaches the pattern O1 forbids: trusting the cached root of a received template. Outside the code, operators can mitigate it by re-storing a received template with `--clear-hash-tree` before handing it to the player.
