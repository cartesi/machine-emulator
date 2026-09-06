# Cartesi Machine state transition verifier (Solidity)

On-chain Solidity implementation of the Cartesi Machine state transition function. A
machine state is committed on-chain as a Merkle root, while its contents are known only
off-chain. A binary step log carries the touched pages plus the sibling hashes needed to
recompute that root; given one, this library replays a single state transition and checks
the root before and after against the commitment. The chain can thus verify one transition
without holding the full machine state.

Three kinds of transition can be verified:

- a single microarchitecture (uarch) step,
- a uarch reset,
- a `send_cmio_response`.

The libraries that execute them (`UArchStep`, `UArchReset`, `SendCmioResponse`) are
transpiled directly from the emulator's C++ sources, so on-chain execution is bit-for-bit
identical to the off-chain machine. The same library is used for both testing (replaying
emulator-generated fixtures) and on-chain dispute verification (used by dave /
rollups-contracts).

## Quick start

Requires Foundry. The top-level README's requirements section pins the version and lists the
install steps, alongside the other toolchains.

```bash
make            # compile contracts (same as `make build`)
make fixtures   # record step-log fixtures from the emulator
make test       # run the Foundry test suite
```

## Generated sources

Some `src/` files are not hand-written: the transpiled handlers (`UArchStep`, `UArchReset`,
`SendCmioResponse`) and the exported `EmulatorConstants`. After changing the emulator
sources they derive from, regenerate and commit:

```bash
make gen-all        # regenerate (needs a built emulator + Foundry)
make check-gen-all  # check for drift without regenerating (what CI runs)
```

`check-gen-all` fails with a diff naming any stale file.
