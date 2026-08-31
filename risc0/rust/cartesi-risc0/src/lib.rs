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
    default_prover,
    sha::{Digest, Digestible},
    ExecutorEnv, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerReceipt, MaybePruned,
    ProverOpts, Receipt, ReceiptClaim,
};

pub use methods::{REPLAY_STEP_ELF, REPLAY_STEP_ID};

/// Journal layout (ABI-encoded, 96 bytes):
/// - root_hash_before: bytes32 (32 bytes)
/// - mcycle_count: uint64 padded to 32 bytes (24 zero bytes + 8 bytes big-endian)
/// - root_hash_after: bytes32 (32 bytes)
///
/// This matches Solidity's `abi.encode(bytes32, uint64, bytes32)`.
pub const JOURNAL_SIZE: usize = 96;

/// Decode the ABI-encoded journal bytes (96 bytes) into its components.
fn decode_journal(bytes: &[u8]) -> (MachineHash, u64, MachineHash) {
    assert!(
        bytes.len() == JOURNAL_SIZE,
        "Journal must be {} bytes (abi.encode format), got {}",
        JOURNAL_SIZE,
        bytes.len()
    );
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
    try_prove(
        guest_elf,
        root_hash_before,
        log_file_path,
        mcycle_count,
        root_hash_after,
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// Like `prove`, but returns the failure as an `Err` instead of panicking. A structurally
/// invalid log makes the guest abort via `zk_abort_with_msg`, surfaced here with the same
/// message the C++ host throws; a caller belief that disagrees with the journal is reported
/// too.
pub fn try_prove(
    guest_elf: &[u8],
    root_hash_before: &MachineHash,
    log_file_path: &str,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> Result<Receipt, String> {
    let log_data = fs::read(log_file_path).map_err(|e| format!("could not read log file: {e}"))?;
    // Guest input: the cycle count to run, then the log bytes (see methods/guest main.rs).
    let env = ExecutorEnv::builder()
        .write_slice(&mcycle_count.to_le_bytes())
        .write_slice(&log_data)
        .build()
        .map_err(|e| format!("could not build executor env: {e}"))?;

    let prover = default_prover();
    let receipt = prover
        .prove_with_opts(env, guest_elf, &ProverOpts::default())
        .map_err(|e| format!("{e:?}"))?
        .receipt;

    let (j_hash_before, j_mcycle, j_hash_after) = decode_journal(&receipt.journal.bytes);
    if j_hash_before != *root_hash_before {
        return Err("root_hash_before mismatch: argument does not match journal".to_string());
    }
    if j_mcycle != mcycle_count {
        return Err("mcycle_count mismatch: argument does not match journal".to_string());
    }
    if j_hash_after != *root_hash_after {
        return Err("root_hash_after mismatch: argument does not match journal".to_string());
    }

    Ok(receipt)
}

/// Compress a receipt to Groth16 and encode it for Solidity contract consumption.
/// Returns (seal_with_selector, journal_bytes).
pub fn compress(receipt: &Receipt) -> Result<(Vec<u8>, Vec<u8>), String> {
    let prover = default_prover();
    let compressed = prover.compress(&ProverOpts::groth16(), receipt).map_err(|e| {
        format!("Groth16 compression failed (needs r0vm and the Groth16 prover; Docker may be required): {e:?}")
    })?;
    encode_seal_and_journal(&compressed)
}

/// Extract the Groth16 seal and journal from a compressed receipt.
/// The seal is prefixed with a 4-byte verifier selector (derived from Groth16ReceiptVerifierParameters)
/// that the on-chain Verifier Router uses to route to the correct proof system.
fn encode_seal_and_journal(receipt: &Receipt) -> Result<(Vec<u8>, Vec<u8>), String> {
    let raw_seal = receipt
        .inner
        .groth16()
        .map_err(|e| format!("compressed receipt is not a Groth16 receipt: {e:?}"))?
        .seal
        .clone();
    let params_digest = Groth16ReceiptVerifierParameters::default().digest();
    let selector = &params_digest.as_bytes()[..4];
    let mut seal = Vec::with_capacity(4 + raw_seal.len());
    seal.extend_from_slice(selector);
    seal.extend_from_slice(&raw_seal);
    Ok((seal, receipt.journal.bytes.clone()))
}

/// Reconstruct and verify a Groth16 receipt from seal (260 bytes) and journal bytes.
/// The seal must include the 4-byte verifier selector prefix used by the on-chain
/// Verifier Router to dispatch to the correct proof system.
pub fn verify_seal(
    image_id: &[u32; 8],
    seal: &[u8],
    journal_bytes: &[u8],
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
) -> (MachineHash, u64, MachineHash) {
    assert!(
        seal.len() == 260,
        "seal must be 260 bytes (4-byte selector + 256-byte proof), got {}",
        seal.len()
    );
    // The seal prefix selects the on-chain verifier; a seal carrying a different selector would route
    // elsewhere (or fail) in the Verifier Router, so reject it here instead of silently dropping it.
    let verifier_parameters = Groth16ReceiptVerifierParameters::default().digest();
    assert!(
        seal[..4] == verifier_parameters.as_bytes()[..4],
        "seal selector does not match the expected Groth16 verifier parameters"
    );
    let raw_seal = &seal[4..];
    let image_id_digest: Digest = (*image_id).into();
    let claim = ReceiptClaim::ok(image_id_digest, journal_bytes.to_vec());
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
    assert!(
        j_hash_before == *root_hash_before,
        "root_hash_before mismatch: argument does not match journal"
    );
    assert!(
        j_mcycle == mcycle_count,
        "mcycle_count mismatch: argument does not match journal"
    );
    assert!(
        j_hash_after == *root_hash_after,
        "root_hash_after mismatch: argument does not match journal"
    );
    (j_hash_before, j_mcycle, j_hash_after)
}

/// Human-readable kind of a receipt's inner proof. "fake" receipts come from
/// RISC0_DEV_MODE proving and carry no cryptographic proof.
pub fn receipt_kind(receipt: &Receipt) -> &'static str {
    match receipt.inner {
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Groth16(_) => "groth16",
        InnerReceipt::Fake(_) => "fake",
        _ => "unknown",
    }
}

/// `allow_dev_mode` gates fake (dev-mode) receipts: the receipt file is untrusted input,
/// and risc0 accepts a fake receipt whenever RISC0_DEV_MODE is set in the environment, so
/// acceptance must be an explicit caller decision, not ambient shell state.
pub fn verify(
    image_id: &[u32; 8],
    receipt: &Receipt,
    root_hash_before: &MachineHash,
    mcycle_count: u64,
    root_hash_after: &MachineHash,
    allow_dev_mode: bool,
) -> (MachineHash, u64, MachineHash) {
    if matches!(receipt.inner, InnerReceipt::Fake(_)) {
        assert!(
            allow_dev_mode,
            "dev-mode (fake) receipt rejected: it carries no cryptographic proof; \
             pass --allow-dev-mode to accept it for testing"
        );
        // Makes the opt-in self-sufficient: risc0 only verifies fake receipts when
        // RISC0_DEV_MODE is set at verification time.
        std::env::set_var("RISC0_DEV_MODE", "1");
    }
    receipt.verify(*image_id).unwrap();
    let (j_hash_before, j_mcycle, j_hash_after) = decode_journal(&receipt.journal.bytes);
    assert!(
        j_hash_before == *root_hash_before,
        "root_hash_before mismatch: argument does not match journal"
    );
    assert!(
        j_mcycle == mcycle_count,
        "mcycle_count mismatch: argument does not match journal"
    );
    assert!(
        j_hash_after == *root_hash_after,
        "root_hash_after mismatch: argument does not match journal"
    );
    (j_hash_before, j_mcycle, j_hash_after)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The seal's 4-byte selector prefix routes the on-chain Verifier Router.
    #[test]
    #[should_panic(expected = "seal selector does not match")]
    fn verify_seal_rejects_wrong_selector() {
        let selector = Groth16ReceiptVerifierParameters::default().digest();
        let mut seal = vec![0u8; 260];
        seal[..4].copy_from_slice(&selector.as_bytes()[..4]);
        seal[0] ^= 0xff; // corrupt the selector
        let zero: MachineHash = [0u8; 32];
        verify_seal(&[0u32; 8], &seal, &[0u8; 96], &zero, 0, &zero);
    }
}
