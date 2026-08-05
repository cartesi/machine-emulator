// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

//! Step log proving over SP1.
//!
//! The proof mode is fixed before proving and there is no way to wrap an
//! existing core proof, so the mode is an argument to `prove` and a Groth16
//! proof costs a full prove rather than an incremental wrap.

use std::fs;

use sp1_sdk::{
    Elf, ExecutionReport, HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofWithPublicValues,
    SP1PublicValues, SP1Stdin,
};

pub type MachineHash = [u8; 32];

/// Journal layout (ABI-encoded, 96 bytes):
/// - root_hash_before: bytes32
/// - mcycle_count: uint64 padded to 32 bytes (24 zero bytes + 8 bytes big-endian)
/// - root_hash_after: bytes32
///
/// This matches Solidity's `abi.encode(bytes32, uint64, bytes32)`.
pub const JOURNAL_SIZE: usize = 96;

/// Proof mode. `Core` is a STARK; `Groth16` is the on-chain form and must be
/// chosen before proving, not derived from a core proof afterwards.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Core,
    Groth16,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "core" => Ok(Self::Core),
            "groth16" => Ok(Self::Groth16),
            other => Err(format!(
                "unknown proof mode {other:?}, expected core or groth16"
            )),
        }
    }
}

/// Decode the ABI-encoded journal bytes (96 bytes) into its components.
fn decode_journal(bytes: &[u8]) -> Result<(MachineHash, u64, MachineHash), String> {
    if bytes.len() != JOURNAL_SIZE {
        return Err(format!(
            "journal must be {JOURNAL_SIZE} bytes (abi.encode format), got {}",
            bytes.len()
        ));
    }
    let mut root_hash_before = [0u8; 32];
    root_hash_before.copy_from_slice(&bytes[0..32]);
    let mcycle_count = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
    let mut root_hash_after = [0u8; 32];
    root_hash_after.copy_from_slice(&bytes[64..96]);
    Ok((root_hash_before, mcycle_count, root_hash_after))
}

/// Check a journal against what the caller claims it proves. Separate from
/// cryptographic verification: this is the layer that catches a caller holding
/// a valid proof of something other than what they asked about.
fn check_journal(
    journal: &[u8],
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Result<(), String> {
    let (j_before, j_mcycle, j_after) = decode_journal(journal)?;
    if j_before != *root_hash_before {
        return Err("root_hash_before mismatch: argument does not match journal".to_string());
    }
    if j_mcycle != mcycle_count {
        return Err("mcycle_count mismatch: argument does not match journal".to_string());
    }
    if j_after != *root_hash_after {
        return Err("root_hash_after mismatch: argument does not match journal".to_string());
    }
    Ok(())
}

/// Read a step log into an SP1 stdin buffer. The whole log must go in a single
/// write_slice: the guest-side read_input returns only the first chunk.
pub fn stdin_for_log(log_file_path: &str) -> Result<SP1Stdin, String> {
    let log_data = fs::read(log_file_path).map_err(|e| format!("could not read log file: {e}"))?;
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&log_data);
    Ok(stdin)
}

/// Run the guest over a step log without proving. Execution is enough to
/// establish rejection — a log the guest aborts on can never be proven — and
/// unlike proving it needs no GPU.
///
/// The exit code check is not optional. A structurally invalid log makes the
/// guest abort via `zk_abort_with_msg`, which halts with code 1, but SP1's
/// executor returns `Ok` for a nonzero halt: only the abort message reaches the
/// process stderr. Without this check a forged log reads as accepted.
pub async fn try_execute<P: Prover>(
    client: &P,
    elf: Elf,
    log_file_path: &str,
) -> Result<(SP1PublicValues, ExecutionReport), String> {
    let stdin = stdin_for_log(log_file_path)?;
    let (public_values, report) = client
        .execute(elf, stdin)
        .await
        .map_err(|e| format!("{e}"))?;
    if report.exit_code != 0 {
        return Err(format!("guest aborted with exit code {}", report.exit_code));
    }
    Ok((public_values, report))
}

/// Prove a step log and check the resulting journal against the caller's claim.
///
/// Executes first. A guest that aborts commits nothing, so proving it would
/// still fail — but only after paying the full proving cost, and reporting an
/// empty journal rather than the reason. Execution costs seconds against
/// minutes and surfaces the guest's own message.
pub async fn prove<P: Prover>(
    client: &P,
    elf: Elf,
    log_file_path: &str,
    mode: Mode,
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Result<SP1ProofWithPublicValues, String> {
    try_execute(client, elf.clone(), log_file_path).await?;
    let stdin = stdin_for_log(log_file_path)?;
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| format!("setup failed: {e}"))?;
    let request = client.prove(&pk, stdin);
    let proof = match mode {
        Mode::Core => request.core().await,
        Mode::Groth16 => request.groth16().await,
    }
    .map_err(|e| format!("proving failed: {e}"))?;
    check_journal(
        proof.public_values.as_slice(),
        root_hash_before,
        mcycle_count,
        root_hash_after,
    )?;
    Ok(proof)
}

/// Verify a saved proof cryptographically, then check its journal against the
/// caller's claim.
pub fn verify<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    proof: &SP1ProofWithPublicValues,
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Result<(), String> {
    client
        .verify(proof, pk.verifying_key(), None)
        .map_err(|e| format!("verification failed: {e}"))?;
    check_journal(
        proof.public_values.as_slice(),
        root_hash_before,
        mcycle_count,
        root_hash_after,
    )
}

/// Verify a Groth16 seal and journal without the prover, the way the on-chain
/// verifier will. The seal carries a 4-byte vkey-hash selector that routes to a
/// verifier on chain, so a seal for a different program fails here rather than
/// silently verifying against ours.
pub fn verify_seal(
    seal: &[u8],
    journal: &[u8],
    vkey_hash: &str,
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Result<(), String> {
    sp1_verifier::Groth16Verifier::verify(
        seal,
        journal,
        vkey_hash,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|e| format!("seal verification failed: {e:?}"))?;
    check_journal(journal, root_hash_before, mcycle_count, root_hash_after)
}

/// The guest's on-chain identity. Deriving it needs a proving key, so it costs
/// a setup.
pub async fn vkey_hash<P: Prover>(client: &P, elf: Elf) -> Result<String, String> {
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| format!("setup failed: {e}"))?;
    Ok(pk.verifying_key().bytes32())
}

/// Write the guest binary and its vkey hash to a directory, so a machine that
/// cannot build the guest can still prove against the canonical one.
pub async fn export_artifacts<P: Prover>(
    client: &P,
    elf: Elf,
    guest_bytes: &[u8],
    output_dir: &str,
) -> Result<String, String> {
    fs::create_dir_all(output_dir).map_err(|e| format!("could not create {output_dir}: {e}"))?;
    let hash = vkey_hash(client, elf).await?;
    fs::write(format!("{output_dir}/guest.elf"), guest_bytes)
        .map_err(|e| format!("could not write guest.elf: {e}"))?;
    fs::write(format!("{output_dir}/vkey-hash.txt"), format!("{hash}\n"))
        .map_err(|e| format!("could not write vkey-hash.txt: {e}"))?;
    Ok(hash)
}

/// Parse a 32-byte hash from hex, with or without a `0x` prefix.
pub fn parse_hash(s: &str) -> Result<MachineHash, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("hash must be 64 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hash {s:?}: {e}"))?;
    }
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(before: u8, mcycle: u64, after: u8) -> Vec<u8> {
        let mut j = vec![0u8; JOURNAL_SIZE];
        j[0..32].fill(before);
        j[56..64].copy_from_slice(&mcycle.to_be_bytes());
        j[64..96].fill(after);
        j
    }

    #[test]
    fn journal_roundtrip() {
        let (b, m, a) = decode_journal(&journal(0xaa, 12345, 0xbb)).unwrap();
        assert_eq!(b, [0xaa; 32]);
        assert_eq!(m, 12345);
        assert_eq!(a, [0xbb; 32]);
    }

    #[test]
    fn wrong_length_journal_is_rejected() {
        assert!(decode_journal(&[0u8; 95]).is_err());
    }

    // A proof is only meaningful against the claim the caller made about it, so
    // each field has to be checked; a mismatch must not be reported as success.
    #[test]
    fn check_journal_catches_each_field() {
        let j = journal(0xaa, 7, 0xbb);
        assert!(check_journal(&j, &[0xaa; 32], 7, &[0xbb; 32]).is_ok());
        assert!(check_journal(&j, &[0xcc; 32], 7, &[0xbb; 32]).is_err());
        assert!(check_journal(&j, &[0xaa; 32], 8, &[0xbb; 32]).is_err());
        assert!(check_journal(&j, &[0xaa; 32], 7, &[0xcc; 32]).is_err());
    }

    #[test]
    fn parse_hash_accepts_both_prefixes() {
        let with = parse_hash("0x00e6b3d37dabb6d5e104909838f6534cc48e85bf5f13a35ad4820ad9b45a936d");
        let without =
            parse_hash("00e6b3d37dabb6d5e104909838f6534cc48e85bf5f13a35ad4820ad9b45a936d");
        assert_eq!(with.unwrap(), without.unwrap());
        assert!(parse_hash("00ff").is_err());
    }
}
