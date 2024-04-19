---
title: Introduction

---

This section describes the Cartesi Machine from the perspective of the blockchain.
Using the Cartesi platform, smart contracts gain a new ability.
They can get their users to agree on the results of computations that cannot be performed natively as smart contracts: computations that either involve too much data, are too computationally demanding, or require a sophisticated software infrastructure that is simply not available for use on-chain.

Users that have a stake in a given computation are represented off-chain by Cartesi Nodes under their control.
Cartesi Nodes react to Cartesi-enabled smart contracts and instantiate Cartesi Machines to perform the required computations and post the result back to the blockchain.
Since Cartesi Machines are self-contained and reproducible, the results of off-chain computations performed by honest users will agree.
The smart contract can then make decisions of consequence that depend on these results.

When the Cartesi Node representing an honest user identifies an incorrect result posted by a dishonest user, it disputes the result.
The opposing Cartesi Nodes then engage in an automatic dispute resolution protocol presided by the blockchain, which results in the dishonest user being proven wrong.
The smart contract that commanded the computation can then punish the dishonest user and reward the honest one.

The Cartesi Machine emulator is one of a kind.
It doesn't simply emulate the RISC-V ISA to the extent that it can boot a performant operating system based on Linux.
It does so in a way that allows smart contracts to specify computations, replace their inputs, inspect their outputs, and direct the dispute resolution protocol.
