# R8-GOALOUTPUT-1: a committed voucher of a maximal input cannot be executed within one transaction

## What is asserted

The manual's own libcmt example application, `puppet` (`/home/dapp/puppet` in `doc/recipes/rootfs-docs.ext2`,
source in the manual: `voucher:<data> -> cmt_rollup_emit_voucher(msg_sender, 0, data), accept`), receives an
advance-state input whose ABI-encoded `EvmAdvance` is 65,508 bytes, within the 65,536-byte
`CanonicalMachine.INPUT_MAX_SIZE` that the pinned InputBox (cartesi-rollups-contracts 3.0.0-alpha.10) enforces. The
guest emits a 65,348-byte `Voucher(address,uint256,bytes)` and accepts; a second, small input (`voucher:hello`)
is the control. The test checks that the outputs Merkle root the guest left in the tx buffer commits to both
vouchers (indices 0 and 1, full-height tree of 2^63 leaves).

A forge test then deploys the **released** `Application` artifact of the pinned Dave v3.0.0-alpha.7 build
(`bugs/harness/work/dave/released/.../out/Application.sol/Application.json`), with an outputs-root validator that
accepts exactly that settled root (standing in for DaveConsensus), and calls `executeOutput(output, proof)`:

- control (failure = exit 2): both proofs pass `validateOutput`; the large voucher executes when gas is not
  limited; the small voucher executes within one transaction under the cap;
- assertion: the large voucher executes with the execution gas one transaction may carry under Ethereum's
  per-transaction gas cap (EIP-7825, 2^24 = 16,777,216), minus the intrinsic gas of its calldata (21,000 + 4 per
  calldata token, EIP-7623 floor also checked).

On audit/prt2 the execution needs about 19.5 M gas (the per-byte copy in `LibBytes.consumeBytes4`, then
`abi.decode`), about 20.6 M for the whole transaction, against a budget of 15.68 M; `executeOutput` runs out of
gas. The calldata itself (67,588 bytes) fits the 128 KiB txpool limit, so gas is the only limit hit here.

## Requirement

THREAT_MODEL.md, A5: "Conversely, the referee accepts every output that the settled state commits to, whenever
its valid proof is presented. No party can make it stop accepting them." Section 8, Critical: "An honest proof or
transaction that cannot fit the chain's per-transaction limits, other than the delivery proof of an input that A3
requires the input record to refuse." (A3 bounds inputs only; the input used here is one the InputBox accepts.)

Deciding question for the reviewer (not settled by the test): whether A5's "accepts" covers executing a voucher
under per-transaction limits, or only `validateOutput`/`validateOutputHash` (views, which succeed here).

## How to run

```sh
bugs/run.sh R8-GOALOUTPUT-1          # KEEP_TMP=1 keeps the temp dir (outputs, proofs, forge project)
```

Needs the in-tree emulator, `linux.bin`, `doc/recipes/rootfs-docs.ext2`, forge and solc 0.8.30 from the harness,
and the released Dave build. No chain is started. Run time: a few seconds.

## Expected output on audit/prt2

```
input 0: 65508 bytes (InputBox limit 65536), manual yield reason 1, 1 output(s), output bytes 65348
input 1: 324 bytes (InputBox limit 65536), manual yield reason 1, 1 output(s), output bytes 164
settled outputs Merkle root (tx buffer) 0xe27b...dd24 commits to both vouchers
[PASS] test_control()
  large voucher, unlimited gas: success true
  small voucher within the per-transaction cap: success true gas used 117129
[FAIL: A5: executeOutput of a voucher the settled state commits to ...] test_large_voucher_executes_within_one_transaction()
  calldata tokens 269299 execution budget under the 2^24 cap 15679020
  within the cap: success false gas used 15811855
  gas the call needs (unlimited) 19538044
  total transaction gas it needs 20636240
VIOLATED: A5: ...
run.sh: R8-GOALOUTPUT-1: exit 1 (bug present)
```

Exit 0 once `executeOutput` of such a voucher fits one transaction, or once the guest no longer commits to it
(a documented, enforced output-size bound that makes libcmt refuse it: no voucher emitted, or the input rejected).
