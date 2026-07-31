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

//! Runs the SP1 executor over a step log and prints the public values and
//! cycle counts. Spike tool: execution only, no proving.

use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <guest.elf> <step.log> [prove [cpu|cuda] [repeat]]", args[0]);
        std::process::exit(1);
    }
    let elf_bytes = std::fs::read(&args[1]).expect("failed to read guest elf");
    let log_bytes = std::fs::read(&args[2]).expect("failed to read step log");
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));

    let mut stdin = SP1Stdin::new();
    // The whole log must go in a single write_slice: the guest-side read_input
    // returns only the first chunk of the hint stream.
    stdin.write_slice(&log_bytes);

    if args.len() > 3 && args[3] == "prove" {
        // A repeat count reuses one proving key across proofs, separating the
        // fixed setup cost from the per-proof cost.
        let repeat = args.get(5).map_or(1, |n| n.parse().expect("repeat count"));
        match args.get(4).map_or("cpu", String::as_str) {
            "cpu" => prove(ProverClient::builder().cpu().build().await, elf, stdin, repeat).await,
            #[cfg(feature = "cuda")]
            "cuda" => prove(ProverClient::builder().cuda().build().await, elf, stdin, repeat).await,
            #[cfg(not(feature = "cuda"))]
            "cuda" => {
                eprintln!("cuda prover not compiled in; rebuild with --features cuda");
                std::process::exit(1);
            }
            other => {
                eprintln!("unknown prover backend {other:?}, expected cpu or cuda");
                std::process::exit(1);
            }
        }
        return;
    }

    let client = ProverClient::builder().light().build().await;
    let (public_values, report) = client.execute(elf, stdin).await.unwrap();

    let pv = public_values.as_slice();
    println!("public_values ({} bytes):", pv.len());
    if pv.len() == 96 {
        println!("  root_hash_before 0x{}", hex(&pv[0..32]));
        println!("  mcycle_count     {}", u64::from_be_bytes(pv[56..64].try_into().unwrap()));
        println!("  root_hash_after  0x{}", hex(&pv[64..96]));
    } else {
        println!("  raw 0x{}", hex(pv));
    }
    println!("total_instruction_count {}", report.total_instruction_count());
    println!("total_syscall_count     {}", report.total_syscall_count());
    println!("gas                     {:?}", report.gas());
    let mut syscalls: Vec<_> = report.syscall_counts.iter().filter(|(_, n)| **n > 0).collect();
    syscalls.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (name, n) in syscalls {
        println!("  syscall {name:?} {n}");
    }
}

async fn prove<P: Prover>(client: P, elf: Elf, stdin: SP1Stdin, repeat: usize) {
    let start = std::time::Instant::now();
    let pk = client.setup(elf).await.unwrap();
    println!("setup in {:?}", start.elapsed());
    for i in 0..repeat {
        let start = std::time::Instant::now();
        let proof = client.prove(&pk, stdin.clone()).core().await.unwrap();
        println!("proved in {:?} (run {})", start.elapsed(), i + 1);
        client.verify(&proof, pk.verifying_key(), None).unwrap();
        println!("proof verified");
        println!("public_values 0x{}", hex(proof.public_values.as_slice()));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
