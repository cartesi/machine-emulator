# Security Policy

## Supported Versions

Please check that the issue is present in the most recent release of the Cartesi Machine emulator before reporting it.

## Reporting a Vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately by email to `rollups@cartesi.foundation`. Include the affected component and version, the impact,
and steps to reproduce.

## What Counts as a Vulnerability

[`THREAT_MODEL.md`](THREAT_MODEL.md) defines what the emulator must guarantee, what it relies on validators and
deployments to do, and how severe a defect is. Please state in your report which of its rules or obligations the
problem violates, and how you rated it.

The on-chain state transition verifier lives in
[machine-solidity-step](https://github.com/cartesi/machine-solidity-step), and the guest tools in
[machine-guest-tools](https://github.com/cartesi/machine-guest-tools). Report problems in either to the same address.
The Dave contracts, the sling node and the Cartesi Rollups Node are maintained in their own repositories.

## What Happens Next

We review each report, decide how to handle it, and reply with the outcome.

Please give us a reasonable time to fix an issue before you disclose it publicly.
