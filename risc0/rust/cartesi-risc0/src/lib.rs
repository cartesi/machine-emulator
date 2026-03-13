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

use std::fs;

pub type MachineHash = [u8; 32];
use risc0_zkvm::{
    default_prover, ExecutorEnv, Groth16Receipt, Groth16ReceiptVerifierParameters,
    InnerReceipt, MaybePruned, ProverOpts, Receipt, ReceiptClaim,
    sha::{Digest, Digestible},
};

pub use methods::{REPLAY_STEP_ELF, REPLAY_STEP_ID};

/// Step log header layout:
/// - root_hash_before: 32 bytes
/// - mcycle_count: 8 bytes (u64 little-endian)
/// - root_hash_after: 32 bytes
pub const STEP_LOG_HEADER_SIZE: usize = 32 + 8 + 32;

/// Journal layout (ABI-encoded, 96 bytes):
/// - root_hash_before: bytes32 (32 bytes)
/// - mcycle_count: uint64 padded to 32 bytes (24 zero bytes + 8 bytes big-endian)
/// - root_hash_after: bytes32 (32 bytes)
///
/// This matches Solidity's `abi.encode(bytes32, uint64, bytes32)`.
pub const JOURNAL_SIZE: usize = 96;

/// Decode the ABI-encoded journal bytes (96 bytes) into its components.
fn decode_journal(bytes: &[u8]) -> (MachineHash, u64, MachineHash) {
    assert!(bytes.len() == JOURNAL_SIZE, "Journal must be {} bytes (abi.encode format), got {}", JOURNAL_SIZE, bytes.len());
    let mut root_hash_before = [0u8; 32];
    root_hash_before.copy_from_slice(&bytes[0..32]);
    let mcycle_count = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
    let mut root_hash_after = [0u8; 32];
    root_hash_after.copy_from_slice(&bytes[64..96]);
    (root_hash_before, mcycle_count, root_hash_after)
}

/// Compute the Image ID from a guest binary (R0BF format).
pub fn guest_image_id(guest_elf: &[u8]) -> [u32; 8] {
    risc0_binfmt::compute_image_id(guest_elf)
        .expect("Failed to compute image ID from guest ELF")
        .into()
}

pub fn prove(
    guest_elf: &[u8],
    root_hash_before: &MachineHash,
    log_file_path: &str,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Receipt {
    let log_data = fs::read(log_file_path).expect("Could not read log file");
    let env = ExecutorEnv::builder()
        .write_slice(&log_data)
        .build()
        .unwrap();

    let prover = default_prover();
    let receipt = prover.prove_with_opts(env, guest_elf, &ProverOpts::default()).unwrap().receipt;

    let (j_hash_before, j_mcycle, j_hash_after) = decode_journal(&receipt.journal.bytes);
    assert!(j_hash_before == *root_hash_before, "root_hash_before mismatch: argument does not match journal");
    assert!(j_mcycle == mcycle_count, "mcycle_count mismatch: argument does not match journal");
    assert!(j_hash_after == *root_hash_after, "root_hash_after mismatch: argument does not match journal");

    receipt
}

/// Compress a receipt to Groth16 and encode it for Solidity contract consumption.
/// Returns (seal_with_selector, journal_bytes).
pub fn compress(receipt: &Receipt) -> (Vec<u8>, Vec<u8>) {
    let prover = default_prover();
    let compressed = prover.compress(&ProverOpts::groth16(), receipt).unwrap();
    encode_seal_and_journal(&compressed)
}

/// Extract the Groth16 seal and journal from a compressed receipt.
/// The seal is prefixed with a 4-byte verifier selector (derived from Groth16ReceiptVerifierParameters)
/// that the on-chain Verifier Router uses to route to the correct proof system.
pub fn encode_seal_and_journal(receipt: &Receipt) -> (Vec<u8>, Vec<u8>) {
    let raw_seal = receipt.inner.groth16().unwrap().seal.clone();
    let params_digest = Groth16ReceiptVerifierParameters::default().digest();
    let selector = &params_digest.as_bytes()[..4];
    let mut seal = Vec::with_capacity(4 + raw_seal.len());
    seal.extend_from_slice(selector);
    seal.extend_from_slice(&raw_seal);
    (seal, receipt.journal.bytes.clone())
}

/// Reconstruct and verify a Groth16 receipt from seal and journal bytes.
/// Accepts seal with (260 bytes) or without (256 bytes) the 4-byte selector prefix.
pub fn verify_seal(
    image_id: &[u32; 8],
    seal: &[u8],
    journal_bytes: &[u8],
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> (MachineHash, u64, MachineHash) {
    let raw_seal = if seal.len() == 260 { &seal[4..] } else { seal };
    let image_id_digest: Digest = (*image_id).into();
    let claim = ReceiptClaim::ok(image_id_digest, journal_bytes.to_vec());
    let verifier_parameters = Groth16ReceiptVerifierParameters::default().digest();
    let groth16_receipt = Groth16Receipt::new(
        raw_seal.to_vec(),
        MaybePruned::Value(claim),
        verifier_parameters,
    );
    let receipt = Receipt::new(
        InnerReceipt::Groth16(groth16_receipt),
        journal_bytes.to_vec(),
    );
    receipt.verify(*image_id).unwrap();
    let (j_hash_before, j_mcycle, j_hash_after) = decode_journal(journal_bytes);
    assert!(j_hash_before == *root_hash_before, "root_hash_before mismatch: argument does not match journal");
    assert!(j_mcycle == mcycle_count, "mcycle_count mismatch: argument does not match journal");
    assert!(j_hash_after == *root_hash_after, "root_hash_after mismatch: argument does not match journal");
    (j_hash_before, j_mcycle, j_hash_after)
}

pub fn verify(
    image_id: &[u32; 8],
    receipt: &Receipt,
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> (MachineHash, u64, MachineHash) {
    receipt.verify(*image_id).unwrap();
    let (j_hash_before, j_mcycle, j_hash_after) = decode_journal(&receipt.journal.bytes);
    assert!(j_hash_before == *root_hash_before, "root_hash_before mismatch: argument does not match journal");
    assert!(j_mcycle == mcycle_count, "mcycle_count mismatch: argument does not match journal");
    assert!(j_hash_after == *root_hash_after, "root_hash_after mismatch: argument does not match journal");
    (j_hash_before, j_mcycle, j_hash_after)
}
