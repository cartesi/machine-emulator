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

//! Command line interface for proving Cartesi step logs over SP1.

use std::{fs, process::exit};

use cartesi_sp1::{
    export_artifacts, hex, parse_hash, prove, try_execute, verify, verify_seal, vkey_hash,
    MachineHash, Mode,
};
use sp1_sdk::{Elf, Prover, ProverClient, SP1ProofWithPublicValues};

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} --guest-elf <path> [options] <command> <args>

Options:
  --guest-elf <path>   Guest binary to prove against (required)
  --prover <backend>   cpu (default) or cuda

Commands:
  execute <log_file_path>
  prove <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <proof-path> [mode]
        mode is core (default) or groth16. The mode is fixed before proving,
        so a groth16 proof is a full prove rather than a wrap of a core proof.
  seal <proof-path> <seal-path> <journal-path>
        Split a groth16 proof into the seal and journal a contract consumes.
  verify <proof-path> <root_hash_before> <mcycle_count> <root_hash_after>
  verify-seal <seal-path> <journal-path> <vkey_hash> <root_hash_before> <mcycle_count> <root_hash_after>
  export-artifacts <output-dir>
  vkey                 Print the guest's vkey hash (SP1's analog of an Image ID)"
    );
}

/// Generic in the return type so it can be passed straight to `unwrap_or_else`,
/// which needs the closure to yield the Ok type rather than `!`.
fn die<T>(message: impl std::fmt::Display) -> T {
    eprintln!("Error: {message}");
    exit(1);
}

/// Same, for statement position, where a generic return type cannot be inferred.
fn bad_usage(message: &str) -> ! {
    eprintln!("Error: {message}");
    exit(1);
}

/// Runs `body` against whichever prover backend was selected. The two clients
/// are different types implementing the same trait, so the choice cannot be
/// boxed away and has to be made at the call site.
macro_rules! with_prover {
    ($backend:expr, |$client:ident| $body:expr) => {
        match $backend {
            "cpu" => {
                let $client = ProverClient::builder().cpu().build().await;
                $body
            }
            #[cfg(feature = "cuda")]
            "cuda" => {
                let $client = ProverClient::builder().cuda().build().await;
                $body
            }
            #[cfg(not(feature = "cuda"))]
            "cuda" => bad_usage("cuda prover not compiled in; rebuild with --features cuda"),
            other => die(format!("unknown prover {other:?}, expected cpu or cuda")),
        }
    };
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv[0].clone();

    let mut guest_elf_path: Option<String> = None;
    let mut backend = "cpu".to_string();
    let mut args: Vec<String> = vec![program.clone()];
    let mut iter = argv.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--guest-elf" => {
                guest_elf_path = Some(
                    iter.next()
                        .unwrap_or_else(|| die("--guest-elf requires a path")),
                )
            }
            "--prover" => {
                backend = iter
                    .next()
                    .unwrap_or_else(|| die("--prover requires a backend"))
            }
            _ => args.push(arg),
        }
    }

    if args.len() < 2 {
        usage(&program);
        exit(1);
    }

    let guest_path = guest_elf_path.unwrap_or_else(|| die("--guest-elf is required"));
    let guest_bytes = fs::read(&guest_path).unwrap_or_else(|e| die(format!("{guest_path}: {e}")));
    let elf = Elf::Static(Box::leak(guest_bytes.clone().into_boxed_slice()));

    match args[1].as_str() {
        "help" => usage(&program),

        "execute" => {
            let log = args
                .get(2)
                .unwrap_or_else(|| die("execute needs <log_file_path>"));
            let client = ProverClient::builder().light().build().await;
            let (public_values, report) = try_execute(&client, elf, log).await.unwrap_or_else(die);
            print_public_values(public_values.as_slice());
            println!(
                "total_instruction_count {}",
                report.total_instruction_count()
            );
            println!("total_syscall_count     {}", report.total_syscall_count());
            println!("gas                     {:?}", report.gas());
        }

        "prove" => {
            if args.len() < 7 || args.len() > 8 {
                bad_usage("prove <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after> <proof-path> [mode]");
            }
            let before = parse_hash(&args[2]).unwrap_or_else(die);
            let log = args[3].clone();
            let mcycle: u64 = args[4]
                .parse()
                .unwrap_or_else(|e| die(format!("mcycle_count: {e}")));
            let after = parse_hash(&args[5]).unwrap_or_else(die);
            let proof_path = args[6].clone();
            let mode = Mode::parse(args.get(7).map_or("core", String::as_str)).unwrap_or_else(die);

            let proof = with_prover!(backend.as_str(), |client| {
                prove(&client, elf, &log, mode, &before, mcycle, &after)
                    .await
                    .unwrap_or_else(die)
            });
            proof
                .save(&proof_path)
                .unwrap_or_else(|e| die(format!("saving proof: {e}")));
            println!("Proof saved to: {proof_path}");
            print_public_values(proof.public_values.as_slice());
        }

        "seal" => {
            if args.len() != 5 {
                bad_usage("seal <proof-path> <seal-path> <journal-path>");
            }
            let proof = SP1ProofWithPublicValues::load(&args[2])
                .unwrap_or_else(|e| die(format!("loading proof: {e}")));
            let seal = proof.bytes();
            if seal.is_empty() {
                bad_usage(
                    "proof carries no seal: it is not a groth16 proof (prove with mode groth16)",
                );
            }
            fs::write(&args[3], &seal).unwrap_or_else(|e| die(format!("writing seal: {e}")));
            fs::write(&args[4], proof.public_values.as_slice())
                .unwrap_or_else(|e| die(format!("writing journal: {e}")));
            println!("Seal ({} bytes) saved to: {}", seal.len(), args[3]);
            println!("Journal saved to: {}", args[4]);
        }

        "verify" => {
            if args.len() != 6 {
                bad_usage(
                    "verify <proof-path> <root_hash_before> <mcycle_count> <root_hash_after>",
                );
            }
            let proof = SP1ProofWithPublicValues::load(&args[2])
                .unwrap_or_else(|e| die(format!("loading proof: {e}")));
            let before = parse_hash(&args[3]).unwrap_or_else(die);
            let mcycle: u64 = args[4]
                .parse()
                .unwrap_or_else(|e| die(format!("mcycle_count: {e}")));
            let after = parse_hash(&args[5]).unwrap_or_else(die);

            with_prover!(backend.as_str(), |client| {
                let pk = client
                    .setup(elf)
                    .await
                    .unwrap_or_else(|e| die(format!("setup: {e}")));
                verify(&client, &pk, &proof, &before, mcycle, &after).unwrap_or_else(die)
            });
            println!("Proof verified");
            print_public_values(proof.public_values.as_slice());
        }

        "verify-seal" => {
            if args.len() != 8 {
                bad_usage("verify-seal <seal-path> <journal-path> <vkey_hash> <root_hash_before> <mcycle_count> <root_hash_after>");
            }
            let seal = fs::read(&args[2]).unwrap_or_else(|e| die(format!("reading seal: {e}")));
            let journal =
                fs::read(&args[3]).unwrap_or_else(|e| die(format!("reading journal: {e}")));
            let before = parse_hash(&args[5]).unwrap_or_else(die);
            let mcycle: u64 = args[6]
                .parse()
                .unwrap_or_else(|e| die(format!("mcycle_count: {e}")));
            let after = parse_hash(&args[7]).unwrap_or_else(die);
            verify_seal(&seal, &journal, &args[4], &before, mcycle, &after).unwrap_or_else(die);
            println!("Seal verified");
            print_public_values(&journal);
        }

        "export-artifacts" => {
            let dir = args
                .get(2)
                .unwrap_or_else(|| die("export-artifacts <output-dir>"));
            let hash = with_prover!(backend.as_str(), |client| {
                export_artifacts(&client, elf, &guest_bytes, dir)
                    .await
                    .unwrap_or_else(die)
            });
            println!("Exported guest.elf and vkey-hash.txt to {dir}");
            println!("vkey hash: {hash}");
        }

        "vkey" => {
            let hash = with_prover!(backend.as_str(), |client| {
                vkey_hash(&client, elf).await.unwrap_or_else(die)
            });
            println!("{hash}");
        }

        other => {
            eprintln!("Unknown command: {other}");
            usage(&program);
            exit(1);
        }
    }
}

fn print_public_values(pv: &[u8]) {
    println!("public_values ({} bytes):", pv.len());
    if pv.len() == 96 {
        let before: MachineHash = pv[0..32].try_into().unwrap();
        let after: MachineHash = pv[64..96].try_into().unwrap();
        println!("  root_hash_before 0x{}", hex(&before));
        println!(
            "  mcycle_count     {}",
            u64::from_be_bytes(pv[56..64].try_into().unwrap())
        );
        println!("  root_hash_after  0x{}", hex(&after));
    } else {
        println!("  raw 0x{}", hex(pv));
    }
}
