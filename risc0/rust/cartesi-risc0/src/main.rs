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

/* 
This is a command line interface for the RISC-V zkVM prover and verifier.
It allows to prove and verify a Cartesi Machine step log.

How to Use:

1) Run the Cartesi Machine and create a step log.
& cartesi-machine --max-mcycle=0 --log-step=1,/tmp/step.log
Logging step of 1 cycles to /tmp/step.log
0: 5966f76b7b68a6dff484188875225b76c95bb93b563fe178b528c99b95fc154a
1: e76e24259f450418a6323150b3afd6afb22579c3ca0c2473a9e402f83ac69ddc

2) Prove the step log and create a receipt file.

 cargo run --bin cartesi-risc0-cli \
    prove \
    5966f76b7b68a6dff484188875225b76c95bb93b563fe178b528c99b95fc154a \
    /tmp/step.log \
    1 \
    e76e24259f450418a6323150b3afd6afb22579c3ca0c2473a9e402f83ac69ddc \
    /tmp/receipt.bin

3) Verify a receipt file.

 cargo run --bin cartesi-risc0-cli \
    verify \
    /tmp/receipt.bin \
    5966f76b7b68a6dff484188875225b76c95bb93b563fe178b528c99b95fc154a \
    1 \
    e76e24259f450418a6323150b3afd6afb22579c3ca0c2473a9e402f83ac69ddc

*/

use std::{fs, env, error};
use risc0_zkvm::Receipt;
use cartesi_risc0::{prove, verify};
use cartesi_risc0_shared::MachineHash;

fn parse_hash(hex: &str) -> MachineHash {
    let bytes = hex::decode(hex).expect("Invalid hex string");
    let mut array = [0; 32];
    array.copy_from_slice(&bytes);
    array
}

fn prove_and_save_receipt(root_hash_before: MachineHash, log_file_path: &str, mcycle_count: u64, root_hash_after: MachineHash, receipt_path: &str) -> Result<(), Box<dyn error::Error>> {
    println!("Proving...");
    let receipt = prove(&root_hash_before, log_file_path, mcycle_count, &root_hash_after);
    fs::write(receipt_path, bincode::serialize(&receipt)?)?;
    println!("Receipt saved to: {}", receipt_path);
    Ok(())
}

fn verify_receipt(receipt_path: &str, root_hash_before: MachineHash, mcycle_count: u64, root_hash_after: MachineHash) -> Result<(), Box<dyn error::Error>> {
    println!("Verifying...");
    let receipt: Receipt = bincode::deserialize(&fs::read(&receipt_path)?)?;
    verify(&receipt, &root_hash_before, mcycle_count, &root_hash_after);
    println!("Verification successful");
    Ok(())
}

fn usage() {
    eprintln!("Usage: cartesi-risc0-cli <command> <args>");
    eprintln!("Commands:");
    eprintln!("  prove <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <output-receipt-path>");
    eprintln!("  verify <receipt-path> <root_hash_before> <mcycle_count> <root_hash_after>");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> <args>", args[0]);
        std::process::exit(1);
    }
    let command = &args[1];
    match command.as_str() {
        "help" => {
            usage();
            std::process::exit(0);
        }
        "prove" => {
            if args.len() != 7 {
                eprintln!("Usage: {} prove <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <output-receipt-path>", args[0]);
                std::process::exit(1);
            }
            let root_hash_before = parse_hash(&args[2]);
            let log_file_path = &args[3];
            let mcycle_count: u64 = args[4].parse().expect("Invalid step count");
            let root_hash_after = parse_hash(&args[5]);
            let receipt_path = &args[6];
            prove_and_save_receipt(root_hash_before, log_file_path, mcycle_count, root_hash_after, receipt_path).expect("Proof generation failed");
        }
        "verify" => {
            if args.len() != 6 {
                eprintln!("Usage: {} verify <receipt-path> <root_hash_before> <mcycle_count> <root_hash_after>", args[0]);
                std::process::exit(1);
            }
            let receipt_path = &args[2];
            let root_hash_before = parse_hash(&args[3]);
            let mcycle_count: u64 = args[4].parse().expect("Invalid step count");
            let root_hash_after = parse_hash(&args[5]);
            verify_receipt(receipt_path, root_hash_before, mcycle_count, root_hash_after).expect("Verification failed");
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            usage();
            std::process::exit(1);
        }
    }
}
    