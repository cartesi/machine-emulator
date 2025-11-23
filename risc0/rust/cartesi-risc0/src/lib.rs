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

use cartesi_risc0_shared::{ Journal, MachineHash};
use memmap2::MmapOptions;
use std::fs::{File};
use methods::{
    REPLAY_STEP_ELF, REPLAY_STEP_ID
    
};
use risc0_zkvm::{
        default_prover, 
        ExecutorEnv,
        Receipt
    };
   
pub fn prove(root_hash_before: &MachineHash, log_file_path: &str, mcycle_count: u64, root_hash_after: &MachineHash) -> Receipt {
    // mmap the step log file
    let log_file = File::open(log_file_path).expect("Could not open log file");
    let log_file_len = log_file.metadata().expect("Could not get metadata").len();
    let log_file = unsafe {
        MmapOptions::new()
            .len(log_file_len as usize)
            .map(&log_file)
            .expect("Could not memory map log file")
    };
    let mut builder = ExecutorEnv::builder();
    builder.write(&mcycle_count).unwrap();
    builder.write(&root_hash_before).unwrap();
    builder.write(&root_hash_after).unwrap();
    builder.write(&log_file_len).unwrap();
    for i in (0..log_file_len).step_by(1) {
        builder.write(&log_file[i as usize]).unwrap();
    }
    let env = builder.build().unwrap();
    let prover = default_prover();
    let receipt = prover
        .prove(env, REPLAY_STEP_ELF)
        .unwrap().receipt;
    receipt
}

/// Generate proof for contract consumption
/// Returns (seal, journal) as byte vectors ready for ABI encoding
pub fn prove_for_contract(root_hash_before: &MachineHash, log_file_path: &str, mcycle_count: u64, root_hash_after: &MachineHash) -> (Vec<u8>, Vec<u8>) {
    let receipt = prove(root_hash_before, log_file_path, mcycle_count, root_hash_after);
    
    // Extract seal bytes from receipt
    let seal = receipt.inner.groth16().unwrap().seal.clone();
    
    // Decode the journal to get the struct
    let journal: Journal = receipt.journal.decode().unwrap();
    
    // ABI encode the journal fields for the contract
    // Contract expects: abi.decode(journal, (bytes32, uint64, bytes32))
    use ethabi::{encode, Token};
    let journal_abi_encoded = encode(&[
        Token::FixedBytes(journal.root_hash_before.to_vec()),
        Token::Uint(ethabi::Uint::from(journal.mcycle_count)),
        Token::FixedBytes(journal.root_hash_after.to_vec()),
    ]);
    
    (seal, journal_abi_encoded)
}


// todo: return propper error
pub fn verify(receipt: &Receipt,  root_hash_before: &MachineHash, mcycle_count: u64, root_hash_after: &MachineHash)  {
    receipt
        .verify(REPLAY_STEP_ID)
        .unwrap();
    let journal: Journal = receipt.journal.decode().unwrap();
    if journal.root_hash_before != *root_hash_before {
        panic!("root_hash_before mismatch");
    }
    if journal.root_hash_after != *root_hash_after {
        panic!("root_hash_after mismatch");
    }
    if journal.mcycle_count != mcycle_count {
        panic!("mcycle_count mismatch");
    }
}
  