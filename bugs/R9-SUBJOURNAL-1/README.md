# R9-SUBJOURNAL-1: the PRT journal prices large moves above the node's default fee cap and never publishes them

Component: `doc/recipes/prt-transactions.lua` (`methods:fees`, `methods:submit`), used by `doc/recipes/prt-bridge.lua`
(Support; it stands in for the honest operator's "Submitting transactions").

## What is asserted

geth and reth refuse, in `eth_sendRawTransaction` and before the pool, any transaction whose `gas * maxFeePerGas`
exceeds `--rpc.txfeecap`. The default cap is 1 ether (geth `SubmitTransaction -> checkTxFee`). The journal picks
`max_fee = min(2 * base + tip, --max-fee)`, bumps it by 15 % every 3 blocks, and never bounds `gas * max_fee`. Its
gas limit is 2 x `eth_estimateGas`. A refused publication comes back as `{ published = true, publication_error =
-32000 }`. This result has no `blocked` field, so the bridge reports no anomaly and counts the move as published.
When the bump passes `--max-fee`, no candidate is held by the node, so the next candidate starts again at the same
over-cap fee.

The test runs the real journal with crisium's defaults against a private anvil that uses the recipe's parameters and
its own free port, and stops it at the end. The transaction calls a gas-burning contract with 94 000 bytes of padding
calldata, and `eth_estimateGas` reports about 6.29 M, so the journal's gas limit is 12.57 M. That is the size of a
winLeafMatch that delivers a large input: Dave's `Gas.WIN_LEAF_MATCH` is 5.536 M plus 16 gas per proof byte. Anvil
has no fee cap, so `chain.publish` is wrapped to apply geth's check. It decodes the raw transaction with
`cast decode-transaction`, refuses it when `gas * maxFeePerGas > 1 ether`, and forwards it to anvil otherwise. The
journal is called once per block, as the bridge calls it.

- Control, base fee 38 gwei: the journal signs at 77 gwei (0.97 ether), the node accepts it, and it is mined in the
  next block. If this fails, the setup is broken and the test exits 2.
- Test, base fee 40 gwei for 30 blocks: a max fee of base + 1 gwei costs 0.515 ether, under the cap. A transaction
  therefore exists that the node accepts and the next block includes. **Required:** the job is mined within the
  window.

Requirement (THREAT_MODEL R4): "The honest operator observes the chain and submits its transactions within the
dispute clocks." Section 3 rates a Support component by the role it stands in for: "the honest operator for an
implementation of an operator".

## Run

```sh
bugs/run.sh R9-SUBJOURNAL-1        # ~3 s; WINDOW_BLOCKS=N changes the 30-block window
```

## Expected output on audit/prt2 (exit 1)

```
control: base fee 38 gwei, gas limit 12570382 (2 x estimate), node fee cap admits max fee <= 79.55 gwei
control: max fees signed (gwei): 77.00
control: journal outcomes {"published":1}; node accepted 1, refused 0 (fee cap); candidates stored at nonce 0: 1; journal 377710 bytes; account nonce 1; mined after 1 block(s), status 1
test: base fee 40 gwei, gas limit 12570382 (2 x estimate), node fee cap admits max fee <= 79.55 gwei
test: max fees signed (gwei): 81.00 93.15 81.00 93.15 81.00 93.15 81.00 93.15 81.00 93.15
test: journal outcomes {"waiting":20,"published(refused:-32000)":10}; node accepted 0, refused 10 (fee cap); candidates stored at nonce 0: 10; journal 3772831 bytes; account nonce 0; NOT mined within 30 blocks
test: max fee base + 1 gwei would cost 0.515 ether (under the cap)
VIOLATED: R4: the honest operator submits its transactions within the dispute clocks: ...
run.sh: R9-SUBJOURNAL-1: exit 1 (bug present)
```

The max-fee sequence repeats with period 2: 81 gwei, then 93.15 gwei, then the next bump would be 107 gwei, above
`--max-fee`, so it starts again at 81 gwei. A longer window does not help. Every refused attempt also stores another
full candidate, about 377 KB here, and the journal file is rewritten and fsynced before each publication.

## Limits (for the reviewer)

- The node's fee cap is emulated, not run. Its rule and default are those of geth and reth, as remembered from their
  sources. Anvil, which the recipe documents, has no cap.
- The gas comes from a burner contract plus padding, not from a measured winLeafMatch of a 64 KiB input.
- Deciding facts for rating:
  - whether the recipe targets nodes with geth or reth defaults;
  - whether a trusted node's policy refusal counts as a host fault or operator configuration (section 4).
