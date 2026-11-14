# R1-R11-3: hash function not bound to the cached hash-tree data

## What is asserted

`test.lua` creates a small keccak256 machine (64 KiB RAM with some non-zero pages) and stores it into a temporary
directory with `machine:store()`. It loads it, takes `get_initial_config()`, changes only
`hash_tree.hash_function` to `"sha256"` and creates a machine from that config. The config still references the
stored `.sht`, `.phtc`, `.dht` and `.dpt` files, which were computed under keccak256.

The test requires one of these outcomes:

- creation is refused, or
- the new machine hashes its contents under sha256. Its root hash must equal the root of the same contents with the
  tree rebuilt from scratch under sha256 (the same config with every tree file name cleared). Its proof of the first
  RAM page must match the sha256 root of that page's bytes, and `verify_hash_tree()` must return true.

A control checks the comparison method first: under keccak256, reusing the stored tree files gives the same root as
rebuilding them. If the control fails, the test exits 2.

## Requirement

- THREAT_MODEL R9: "The content hash must equal the root of the actual contents. This applies to every cached,
  incremental, or persisted hash, after any sequence of documented operations."
- THREAT_MODEL R11: "Each deployment fixes one hash function, which no proof can select. Every machine it disputes
  uses that hash function for life."
- Manual (doc/README.md, `hash_tree` entry): "These options are mutually exclusive: a machine that was initialized
  for use with the uarch can never be used with the ZK prover (and vice-versa)."
- THREAT_MODEL section 8, Medium: "A machine API operation off the honest operator's path that, used as documented,
  leaves the hash tree ... inconsistent with the machine's contents (R9)."

## How to run

```sh
bugs/run.sh R1-R11-3
```

The test takes a few seconds. `verify_hash_tree()` prints one line for each page that does not match (about 200 KB on
stdout). The verdict lines are at the end.

## Expected output on audit/prt2

Creation succeeds and reuses the keccak256 tree data. The root matches neither content hash:

```
keccak256 root (stored)         	0xe8fa243c...3dbb2a25
sha256 root (rebuilt, reference)	0x20487c02...5b4fc19d
switched machine root           	0x724566d9...faf432e3
  equals sha256 reference       	false
  equals keccak256 root         	false
  RAM page proof matches sha256 	false
  verify_hash_tree()            	false
VIOLATED: R9: ...
run.sh: R1-R11-3: exit 1 (bug present)
```

The test exits 1 on every run. It would exit 0 if creation refused tree data written under another hash function,
or if creation rebuilt that data (marked every page dirty and discarded the sparse tree and the page cache).
