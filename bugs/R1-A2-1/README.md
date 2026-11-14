# R1-A2-1: the recipe referee model does not cap an epoch's inputs at the input limit per epoch

Component: the PRT referee model in `doc/recipes/prt.lua` (`new_dapp_contract`, `run_epoch`), role Referee model
(AUDIT.md). `new_dapp_contract` takes every input path as the epoch's input record (`inputs = map(input_paths,
fs.read_file)`, no bound) and `run_epoch` announces every one of them with `input_added` and seals the epoch with
`#inputs`. The dispute grid of that geometry addresses only 2^24 input slots
(`mcycle_height = 24 + 48 - 10 = 62`, `periods_per_input = 2^38`), so an input at offset >= 2^24 is assigned to the
epoch but has no position; the honest player asserts "input offset past the epoch's input limit" on it.

## Requirement

THREAT_MODEL.md A3: "The input record assigns no more inputs to an epoch than the input limit per epoch."
Section 3 (Referee model): "A defect in what it accepts or derives is rated as if a deployed referee had it."
R4: the honest operator "assigns inputs to epochs exactly as the referee does, including the input limit per epoch
(A3)." The manual's list of model simplifications (doc/README.md, "The model simplifies the PRT contracts in a few
ways") does not mention dropping this limit; the manual states "the maximum number of inputs per epoch (2^24)".

## What the test does

`test.lua` writes a one-byte input file, calls `prt.new_dapp_contract(hash, paths)` with 2^24 + 1 copies of its path
(the model really reads it 2^24 + 1 times), and runs `prt.new_referee(contract):run(server)` against a recording
stand-in for the referee server that counts `input_added` events and records the count of `epoch_sealed`, stopping
the run there (before any tournament). A control run with 3 inputs checks that the stand-in reaches the seal.

* exit 1: the referee sealed the epoch with more than 2^24 inputs (bug present);
* exit 0: it assigned at most 2^24 inputs to the epoch, or refused the oversized record with an error;
* exit 2: setup error (control run did not reach the seal, module not loadable, ...).

Run time about 25 s, peak RSS about 800 MB (two Lua tables of 2^24 + 1 entries).

## Run

```sh
bugs/run.sh R1-A2-1
```

## Expected output on audit/prt2

```
control: 3 inputs -> 3 input_added, epoch_sealed(3)
building the referee's dapp contract from 16777217 input paths...
referee published 16777217 input_added events (offsets 0..16777216, ordered=true) and epoch_sealed(16777217)
dispute grid: 16777216 input slots (mcycle_height 62, periods_per_input 2^38); the input at offset 16777216 has no position
VIOLATED: A3: the input record assigns no more inputs to an epoch than the input limit per epoch (16777216); the referee model sealed the epoch with 16777217 inputs
run.sh: R1-A2-1: exit 1 (bug present)
```

Note on reach: the test calls the model's exported Lua entry points. Through the `prt.lua referee` command line the
same record would need 2^24 + 1 path arguments, beyond the exec argument limit; in the model the input record is the
referee's configuration rather than an input box that senders fill. Rating that is for the reviewer.
