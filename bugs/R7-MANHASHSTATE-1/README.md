# R7-MANHASHSTATE-1: the manual's instantiation/extraction "by proof" does not bind the proof to the state hash or the drive

Components: `doc/recipes/splice-calculator-with-new-drive.lua` and `doc/recipes/slice-calculator-output.lua`
(the manual's "Template instantiation" and "Result extraction", the "blockchain way"), built on
`cartesi.hash-tree` `verify_splice`/`verify_slice` (`src/cartesi/hash-tree.lua`). Role: Support (helper library
and demo recipes, standing in for a node-proof verifier).

`verify_slice` checks a proof only against its own `proof.root_hash`, and `verify_splice` only adds
`roll(new_target_hash) == new_root_hash`. Neither receives the known hash M, nor checks `target_address` /
`log2_target_size`. The recipes add only `log2_root_size == 64`. So:

* (A) instantiation: a "pristine input proof" with arbitrary siblings and `root_hash = roll(siblings, anything)`
  makes the recipe accept any M' its forger picks, though the proof's root is not the template hash M;
* (B) extraction: a whole-machine proof of the *input* NVRAM (same size as the output NVRAM, contents chosen by the
  instantiator) is accepted as the output proof, with the input text as the "result".

## Requirement

* Manual (doc/README.md, "Slicing and splicing"): "To verify a slicing operation, the code first checks the root
  hash *M* against the one found in the proof"; splicing "first ... verifies that the slicing operation is valid.
  This ensures that the sibling hashes are correct". "Result extraction": `verify_splice` "confirms that an output
  NVRAM with exactly this content sits in the machine whose state hash is *M'*".
* THREAT_MODEL.md section 1 (soundness failure): "a proof verifier accepts a node that the committed tree does not
  hold at the stated index and height". R11: "Every referee parameter comes from the referee, never from the proof"
  (section 2: the index, height and root of an authenticated node are referee parameters). Section 4: "Logs and
  proofs are adversarial." Section 8: "A contradiction between the manual and the behavior on a security-relevant
  point is a defect in one of the two."

## What the test does

`test.lua` runs the two recipe files themselves, unmodified (`loadfile`), on a small template
(1 MiB RAM, 4 KiB `input` NVRAM at 0xa0000000, 4 KiB `output` NVRAM at 0xb0000000). `cartesi.machine` is replaced
by a stand-in that gives the recipe the chain's view: the real drive layout, the known hash (M before the input
write; the claimed or agreed M' after it) and, for extraction, the prover's claimed result from `read_memory`. The
proof modules (`pristine-input-proof`, `output-proof`) are injected through `package.loaded`. A recipe accepts if it
runs to the end ("... by proof works!") and refuses if it raises.

* Controls: the honest proof with the honest M' (A) and the honest output proof with the real result "2\n" (B) are
  accepted; otherwise exit 2.
* (A) forged pristine-input proof (root != M) with the M' it rolls to (!= real instantiated hash): must be refused.
* (B) real proof of the input NVRAM of the agreed final machine, with result "1+1\n" (real output "2\n"): must be
  refused.

Exit 1 if either is accepted, 0 if both are refused, 2 on setup errors (including a recipe that needs a machine
method the stand-in does not model). Checked during proving: copies of the recipes that add
`proof.root_hash == M` and `target_address`/`log2_target_size` checks against the drive make the test exit 0.

## Run

```sh
bugs/run.sh R7-MANHASHSTATE-1      # about 1 s
```

## Expected output on audit/prt2

```
(A) instantiation: forged proof root == M: false; claimed M' == real instantiated hash: false; recipe accepted: true
(B) extraction: proof target 0xa0000000 (output NVRAM is 0xb0000000); claimed result "1+1\n", real output "2\n"; recipe accepted: true
VIOLATED: (A) instantiation by proof must refuse a pristine-input proof whose root is not the template hash M ...
VIOLATED: (B) extraction by proof must refuse a proof of a node other than the output NVRAM ...
run.sh: R7-MANHASHSTATE-1: exit 1 (bug present)
```
