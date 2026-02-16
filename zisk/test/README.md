# ZisK Tests

Runs the ZisK prover against step logs. Step logs are passed directly
to `ziskemu` as input — no conversion needed.

## Usage

Run all tests with ziskemu (fast):

    make test

Run filtered tests:

    make test FILTER=xori
    make test FILTER=rv64ui-p-add

Run with constraint verification (slow, ~70-80s each):

    make test FILTER=xori verify=yes

Generate proofs (very slow, FILTER required):

    make prove FILTER=xori

Verify generated proofs (FILTER required):

    make verify-proof FILTER=xori

Clean generated files:

    make clean

## Options

    FILTER=<pattern>  Filter tests by pattern (case-insensitive)
    verify=yes        Enable constraint verification
    verbose=no        Suppress detailed output (default: yes)

## Output Files

The test target writes to `outputs/<step-log-name>/`:

    public_output_values.bin      Raw public outputs from ziskemu (72 bytes)

The prove target adds:

    result.json            Proof metadata (cycles, time, id)
    vadcop_final_proof.bin The ZK proof itself (~244KB)

## Public Values

The ZisK program (main.rs) outputs 18 u32 values via `set_output()`:

    0-7   root_hash_before (256 bits, big-endian u32 chunks)
    8-9   mcycle_count (u64 as two u32: high, low)
    10-17 root_hash_after (256 bits, big-endian u32 chunks)

These are the provable public outputs — the ZK proof attests that
executing the step log transforms `root_hash_before` into `root_hash_after`
over `mcycle_count` machine cycles.
