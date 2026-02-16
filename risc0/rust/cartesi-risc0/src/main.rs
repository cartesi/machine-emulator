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

 cargo run --bin cartesi-risc0-cli -- prove \
    5966f76b7b68a6dff484188875225b76c95bb93b563fe178b528c99b95fc154a \
    /tmp/step.log \
    1 \
    e76e24259f450418a6323150b3afd6afb22579c3ca0c2473a9e402f83ac69ddc \
    /tmp/receipt.bin

3) Verify a receipt file.

 cargo run --bin cartesi-risc0-cli -- verify \
    /tmp/receipt.bin \
    5966f76b7b68a6dff484188875225b76c95bb93b563fe178b528c99b95fc154a \
    1 \
    e76e24259f450418a6323150b3afd6afb22579c3ca0c2473a9e402f83ac69ddc

*/

use std::{fs, env, error, path::Path};
use risc0_zkvm::Receipt;
use cartesi_risc0::{prove, encode_receipt_for_solidity, verify, verify_groth16, guest_image_id, REPLAY_STEP_ELF, REPLAY_STEP_ID};
use cartesi_risc0::MachineHash;

fn parse_hash(hex: &str) -> MachineHash {
    let bytes = hex::decode(hex).expect("Invalid hex string");
    let mut array = [0; 32];
    array.copy_from_slice(&bytes);
    array
}

fn hash_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert Image ID ([u32; 8]) to hex string (64 chars)
fn image_id_to_hex(id: &[u32; 8]) -> String {
    id.iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn export_artifacts(guest_elf: &[u8], image_id: &[u32; 8], output_dir: &str) -> Result<(), Box<dyn error::Error>> {
    let output_path = Path::new(output_dir);
    fs::create_dir_all(output_path)?;

    // Write guest binary (R0BF format - RISC0's bundled ELF format)
    // This is what RISC0 provers (Boundless) expect
    let elf_path = output_path.join("cartesi-risc0-guest-step-prover.bin");
    fs::write(&elf_path, guest_elf)?;
    println!("Guest binary written to: {}", elf_path.display());
    println!("  (R0BF format - {} bytes)", guest_elf.len());

    // Write Image ID as hex
    let image_id_hex = image_id_to_hex(image_id);
    let id_path = output_path.join("cartesi-risc0-guest-step-prover-image-id.txt");
    fs::write(&id_path, &image_id_hex)?;
    println!("Image ID written to: {}", id_path.display());
    Ok(())
}

fn prove_and_save_receipt(guest_elf: &[u8], root_hash_before: MachineHash, log_file_path: &str, mcycle_count: u64, root_hash_after: MachineHash, receipt_path: &str, groth16: bool) -> Result<(), Box<dyn error::Error>> {
    println!("Proving step log: {}", log_file_path);
    let receipt = prove(guest_elf, &root_hash_before, log_file_path, mcycle_count, &root_hash_after, groth16);
    fs::write(receipt_path, bincode::serialize(&receipt)?)?;
    println!("Receipt saved to: {}", receipt_path);
    Ok(())
}

fn prove_and_save_solidity_artifacts(guest_elf: &[u8], root_hash_before: MachineHash, log_file_path: &str, mcycle_count: u64, root_hash_after: MachineHash, seal_path: &str, journal_path: &str) -> Result<(), Box<dyn error::Error>> {
    println!("Proving step log for contract (Groth16): {}", log_file_path);
    let receipt = prove(guest_elf, &root_hash_before, log_file_path, mcycle_count, &root_hash_after, true);
    let (seal, journal_abi_encoded) = encode_receipt_for_solidity(&receipt);
    fs::write(seal_path, &seal)?;
    println!("Seal saved to: {} ({} bytes)", seal_path, seal.len());
    fs::write(journal_path, &journal_abi_encoded)?;
    println!("Journal saved to: {} ({} bytes)", journal_path, journal_abi_encoded.len());
    Ok(())
}

fn verify_receipt(image_id: &[u32; 8], receipt_path: &str, root_hash_before: MachineHash, mcycle_count: u64, root_hash_after: MachineHash) -> Result<(), Box<dyn error::Error>> {
    println!("Verifying receipt: {}", receipt_path);
    let receipt: Receipt = bincode::deserialize(&fs::read(receipt_path)?)?;
    let (j_hash_before, j_mcycle, j_hash_after) = verify(image_id, &receipt, &root_hash_before, mcycle_count, &root_hash_after);
    println!("Verification successful");
    println!("Journal contents:");
    println!("  root_hash_before: {}", hash_to_hex(&j_hash_before));
    println!("  mcycle_count: {}", j_mcycle);
    println!("  root_hash_after: {}", hash_to_hex(&j_hash_after));
    Ok(())
}

fn verify_groth16_seal_and_journal(image_id: &[u32; 8], seal_path: &str, journal_path: &str, root_hash_before: MachineHash, mcycle_count: u64, root_hash_after: MachineHash) -> Result<(), Box<dyn error::Error>> {
    println!("Verifying Groth16 seal and journal: seal={}, journal={}", seal_path, journal_path);
    let seal = fs::read(seal_path)?;
    let journal_bytes = fs::read(journal_path)?;
    let (j_hash_before, j_mcycle, j_hash_after) = verify_groth16(image_id, &seal, &journal_bytes, &root_hash_before, mcycle_count, &root_hash_after);
    println!("Verification successful");
    println!("Journal contents:");
    println!("  root_hash_before: {}", hash_to_hex(&j_hash_before));
    println!("  mcycle_count: {}", j_mcycle);
    println!("  root_hash_after: {}", hash_to_hex(&j_hash_after));
    Ok(())
}

fn usage() {
    eprintln!("Usage: cartesi-risc0-cli [options] <command> <args>");
    eprintln!("");
    eprintln!("Options:");
    eprintln!("  --guest-elf <path>  Use a precompiled guest binary (R0BF format) instead of");
    eprintln!("                      the embedded one. Enables canonical Image ID on machines");
    eprintln!("                      built without Docker.");
    eprintln!("  --groth16           Request Groth16 receipt for prove command (requires Docker).");
    eprintln!("");
    eprintln!("Commands:");
    eprintln!("  prove <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <output-receipt-path>");
    eprintln!("  prove-groth16 <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <seal-path> <journal-path>");
    eprintln!("  verify <receipt-path> <root_hash_before> <mcycle_count> <root_hash_after>");
    eprintln!("  verify-groth16 <seal-path> <journal-path> <root_hash_before> <mcycle_count> <root_hash_after>");
    eprintln!("  export-artifacts <output-dir>   Export guest binary and Image ID to directory");
    eprintln!("  image-id                        Print the Image ID");
}

fn main() {
    // Parse flags (can appear anywhere before or after the command)
    let all_args: Vec<String> = env::args().collect();
    let mut guest_elf_path: Option<String> = None;
    let mut groth16_flag = false;
    let mut args: Vec<String> = Vec::new();
    let mut iter = all_args.into_iter();
    args.push(iter.next().unwrap()); // program name
    while let Some(arg) = iter.next() {
        if arg == "--guest-elf" {
            guest_elf_path = Some(iter.next().unwrap_or_else(|| {
                eprintln!("Error: --guest-elf requires a path argument");
                std::process::exit(1);
            }));
        } else if arg == "--groth16" {
            groth16_flag = true;
        } else {
            args.push(arg);
        }
    }

    // Resolve guest ELF and Image ID
    let (guest_elf, image_id): (Vec<u8>, [u32; 8]) = match &guest_elf_path {
        Some(path) => {
            let elf = fs::read(path).unwrap_or_else(|e| {
                eprintln!("Error: Failed to read guest ELF {}: {}", path, e);
                std::process::exit(1);
            });
            let id = guest_image_id(&elf);
            eprintln!("Using guest ELF: {} (Image ID: {})", path, image_id_to_hex(&id));
            (elf, id)
        }
        None => (REPLAY_STEP_ELF.to_vec(), REPLAY_STEP_ID),
    };

    if args.len() < 2 {
        usage();
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
            let mcycle_count: u64 = args[4].parse().expect("Invalid mcycle count");
            let root_hash_after = parse_hash(&args[5]);
            let receipt_path = &args[6];
            prove_and_save_receipt(&guest_elf, root_hash_before, log_file_path, mcycle_count, root_hash_after, receipt_path, groth16_flag).expect("Proof generation failed");
        }
        "prove-groth16" => {
            if args.len() != 8 {
                eprintln!("Usage: {} prove-groth16 <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <seal-path> <journal-path>", args[0]);
                std::process::exit(1);
            }
            let root_hash_before = parse_hash(&args[2]);
            let log_file_path = &args[3];
            let mcycle_count: u64 = args[4].parse().expect("Invalid mcycle count");
            let root_hash_after = parse_hash(&args[5]);
            let seal_path = &args[6];
            let journal_path = &args[7];
            prove_and_save_solidity_artifacts(&guest_elf, root_hash_before, log_file_path, mcycle_count, root_hash_after, seal_path, journal_path).expect("Proof generation failed");
        }
        "verify" => {
            if args.len() != 6 {
                eprintln!("Usage: {} verify <receipt-path> <root_hash_before> <mcycle_count> <root_hash_after>", args[0]);
                std::process::exit(1);
            }
            let receipt_path = &args[2];
            let root_hash_before = parse_hash(&args[3]);
            let mcycle_count: u64 = args[4].parse().expect("Invalid mcycle count");
            let root_hash_after = parse_hash(&args[5]);
            verify_receipt(&image_id, receipt_path, root_hash_before, mcycle_count, root_hash_after).expect("Verification failed");
        }
        "verify-groth16" => {
            if args.len() != 7 {
                eprintln!("Usage: {} verify-groth16 <seal-path> <journal-path> <root_hash_before> <mcycle_count> <root_hash_after>", args[0]);
                std::process::exit(1);
            }
            let seal_path = &args[2];
            let journal_path = &args[3];
            let root_hash_before = parse_hash(&args[4]);
            let mcycle_count: u64 = args[5].parse().expect("Invalid mcycle count");
            let root_hash_after = parse_hash(&args[6]);
            verify_groth16_seal_and_journal(&image_id, seal_path, journal_path, root_hash_before, mcycle_count, root_hash_after).expect("Groth16 verification failed");
        }
        "export-artifacts" => {
            if args.len() != 3 {
                eprintln!("Usage: {} export-artifacts <output-dir>", args[0]);
                std::process::exit(1);
            }
            let output_dir = &args[2];
            export_artifacts(&guest_elf, &image_id, output_dir).expect("Export failed");
        }
        "image-id" => {
            println!("{}", image_id_to_hex(&image_id));
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            usage();
            std::process::exit(1);
        }
    }
}
