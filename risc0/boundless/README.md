# Boundless Remote Proving

Submit Cartesi Machine step proofs to [Boundless](https://beboundless.xyz),
RISC Zero's decentralized proving marketplace. Instead of generating ZK proofs
locally, this workflow uploads the computation to Boundless where GPU-accelerated
provers compete to generate the proof.

**How does Boundless differ from direct Groth16?** See the
[comparison in the parent README](../README.md#on-chain-verification).
In short: Boundless verifies proofs **off-chain** and posts a single
aggregated proof for many computations. On-chain, you only check a
Merkle inclusion path (~50k gas) instead of running a full Groth16
pairing (~300k gas). The trade-off is a dependency on the Boundless
prover network. The on-chain contract interface (SetVerifier) is
different from direct Groth16 (Verifier Router) — they are **not
interchangeable**.

> This guide uses **Sepolia** (Ethereum testnet) and **Pinata** (IPFS pinning
> service) as concrete defaults to make the steps easy to follow. You can
> substitute any EVM-compatible chain supported by Boundless and any IPFS
> provider or S3-compatible storage that suits your needs.

## Prerequisites

Before starting, you need:

- Cartesi Machine Emulator built and working
- RISC0 prover built (`make -C risc0`)
- `jq`, `curl` (typically pre-installed)
- [Foundry](https://getfoundry.sh) installed (`cast` CLI) — optional, for balance checks
- [Boundless CLI](#installing-the-boundless-cli) installed
- A Sepolia wallet funded with testnet ETH
- A Pinata account with a JWT token

## Quick Start

    cp env.example .env
    # Edit .env with your wallet key and Pinata JWT

    source .env
    make artifacts    # Build RISC0 guest binary and compute its Image ID
    make prove        # Run the full pipeline (see below)

The `prove` target chains these steps automatically:

1. **check-env** — validates that required env vars and tools are available
2. **step-log** — runs the Cartesi Machine for `STEP_LOG_MCYCLES` cycles
   and records all state accesses to `build/step.log`
3. **artifacts** — builds the RISC0 guest binary (R0BF format) and computes
   its Image ID (skipped if already built)
4. **upload-guest** — uploads the guest binary to IPFS via Pinata and saves
   its CID (Content Identifier — IPFS's content-addressed hash that
   uniquely identifies the file) to `build/guest-cid.txt`
5. **upload-input** — wraps the step log in GuestEnv V0 format (prepends
   a `0x00` byte), uploads it to IPFS, saves the CID to `build/input-cid.txt`
6. **request** — generates `build/request.yaml` from the template with
   the Image ID, IPFS URLs, and pricing parameters
7. **submit** — submits the request to Boundless and waits for a prover
   to generate and submit the ZK proof on-chain

Each step caches its output in `build/` (e.g., `guest-cid.txt`,
`input-cid.txt`, `request.yaml`). On subsequent runs, steps whose output
files already exist are skipped. To force a full re-run from scratch:

    make clean && make prove

To re-run only specific steps, delete the corresponding file in `build/`
and run `make prove` again.

## Setup

### Creating a Sepolia Wallet

    cast wallet new

Save the private key — you'll need it for `BOUNDLESS_WALLET_KEY` in `.env`.

### Getting Testnet ETH

Fund your wallet with Sepolia ETH from any of these faucets:

- https://cloud.google.com/application/web3/faucet/ethereum/sepolia
- https://faucets.chain.link/sepolia
- https://www.alchemy.com/faucets/ethereum-sepolia

### Getting a Pinata JWT

1. Create a free account at https://pinata.cloud
2. Go to API Keys and create a new key with admin permissions
3. Copy the JWT token for `PINATA_JWT` in `.env`

### Installing Foundry (optional, for balance checks)

Foundry provides the `cast` CLI for interacting with Ethereum.
Install on macOS or Linux:

    curl -L https://foundry.paradigm.xyz | bash
    foundryup

After installation, verify with `cast --version`.

### Installing the Boundless CLI

    RISC0_SKIP_BUILD_KERNELS=1 cargo install --locked \
      --git https://github.com/boundless-xyz/boundless \
      boundless-cli --branch release-1.2 --bin boundless

The `RISC0_SKIP_BUILD_KERNELS=1` flag skips building GPU proving kernels
(Metal on macOS, CUDA on Linux), which are not needed for proof submission.
Without this flag, the build requires Xcode (macOS) or the CUDA toolkit (Linux).

After installation, configure the CLI for Sepolia:

    boundless requestor setup \
      --change-network sepolia \
      --set-rpc-url https://ethereum-sepolia-rpc.publicnode.com \
      --set-private-key $BOUNDLESS_WALLET_KEY

### Environment Variables

Copy `env.example` to `.env` and fill in the required values:

    cp env.example .env

Then source it before running make targets:

    source .env

## Workflow

### Individual Targets

    make step-log         Generate a step log (STEP_LOG_MCYCLES=100)
    make artifacts        Build RISC0 guest binary and Image ID
    make upload-guest     Upload guest binary to IPFS via Pinata
    make upload-input     Wrap step log in GuestEnv format and upload
    make request          Generate request.yaml from template
    make submit           Submit to Boundless and wait for proof
    make check-balance    Check wallet Sepolia ETH balance

### Full Pipeline

    make prove            Run all of the above in sequence

### Customizing

Override any parameter via environment variables or make arguments:

    # Larger step log (more cycles)
    make prove STEP_LOG_MCYCLES=1000

    # Higher pricing for faster fulfillment
    make prove MIN_PRICE_ETH=0.005 MAX_PRICE_ETH=0.02

    # Longer timeout for large proofs
    make prove TIMEOUT=7200

## How It Works

1. **Step log generation** — `cartesi-machine.lua` runs the Cartesi Machine
   for the specified number of cycles and records all state accesses.

2. **RISC0 artifacts** — The guest binary (R0BF format) and its Image ID
   are built from the RISC0 prover source.

3. **IPFS upload** — Both the guest binary and the step log (wrapped in
   GuestEnv V0 format) are uploaded to IPFS via Pinata's REST API.

4. **Request generation** — A YAML request file is generated with the IPFS
   URLs, Image ID, and pricing parameters.

5. **Boundless submission** — The request is submitted to the Boundless
   marketplace. Provers download the guest program and input, execute the
   computation inside the RISC Zero zkVM, and submit the proof on-chain.

### GuestEnv V0 Format

Boundless expects inputs wrapped in GuestEnv V0 format: a `0x00` byte
prepended to the raw input data. The Makefile handles this automatically.

### Pricing (Reverse Dutch Auction)

Boundless uses a reverse Dutch auction for proof pricing:
- Price starts at `MIN_PRICE_ETH` and increases over `RAMP_UP_PERIOD`
  seconds toward `MAX_PRICE_ETH`.
- Provers lock the request when the price reaches their threshold.
- If no prover locks within `TIMEOUT` seconds, the request expires.
- For larger proofs (more cycles), use higher prices and longer timeouts.

## Troubleshooting

**"version mismatch" or preflight errors**

The `--no-preflight` flag is already set in the Makefile. If you see
version-related errors, ensure your Boundless CLI and RISC0 toolchain
versions are compatible.

**"request expired" or "no prover locked"**

Increase `MAX_PRICE_ETH` or `TIMEOUT`. For 100k+ cycle proofs, try:

    make prove MAX_PRICE_ETH=0.02 TIMEOUT=7200

**"insufficient balance"**

Check your wallet balance:

    make check-balance

Get more Sepolia ETH from the faucets listed above.

**IPFS upload fails with "Unauthorized"**

Your Pinata JWT may have expired or lack permissions. Generate a new API
key with admin permissions at https://app.pinata.cloud/developers/api-keys.
