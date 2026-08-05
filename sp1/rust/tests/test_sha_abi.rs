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
//! The sha precompiles address their buffers as arrays of 8-byte slots holding
//! u32 values, which the C header does not say. A build that got that wrong
//! would produce wrong hashes, and the first symptom would be a root-hash
//! mismatch on an unrelated fixture.
//!
//! These vectors hash through the guest's own primitives and compare against a
//! reference SHA-256. They are chosen so a wrong slot stride or a wrong byte
//! order cannot coincide with the right answer: an all-zero or symmetric input
//! would hash the same either way.
//!
//! Build the guest with `make -C sp1/cpp sha-abi-guest.elf`.

use std::{fs, path::PathBuf};

use cartesi_sp1::try_execute;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, ProverClient};

const TAG_LEAF: u8 = 0;
const TAG_CONCAT: u8 = 1;

fn guest() -> Elf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sp1 dir")
        .join("cpp/sha-abi-guest.elf");
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!("{}: {e}. Run make -C sp1/cpp sha-abi-guest.elf", path.display())
    });
    Elf::Static(Box::leak(bytes.into_boxed_slice()))
}

/// Distinguishing inputs. Byte-order errors show up when the four bytes of a
/// word differ; stride errors show up when adjacent words differ.
fn vectors() -> Vec<(u8, Vec<u8>)> {
    let incrementing: Vec<u8> = (0u8..32).collect();
    let high_bits: Vec<u8> = (0u8..32).map(|i| 0x80 | i).collect();
    let all_ff = vec![0xffu8; 32];
    let mut concat_incrementing: Vec<u8> = (0u8..64).collect();
    concat_incrementing[0] = 0xfe; // break the symmetry between the halves
    let concat_mixed: Vec<u8> = (0u8..64).map(|i| if i % 2 == 0 { i } else { 0xff - i }).collect();

    vec![
        (TAG_LEAF, incrementing),
        (TAG_LEAF, high_bits),
        (TAG_LEAF, all_ff),
        (TAG_CONCAT, concat_incrementing),
        (TAG_CONCAT, concat_mixed),
    ]
}

#[tokio::test]
async fn precompile_digests_match_reference_sha256() {
    let cases = vectors();

    let mut input = Vec::new();
    for (tag, operand) in &cases {
        input.push(*tag);
        input.extend_from_slice(operand);
    }
    let log = std::env::temp_dir().join("sp1-sha-abi-vectors.bin");
    fs::write(&log, &input).expect("write vectors");

    let client = ProverClient::builder().light().build().await;
    let (public_values, _) = try_execute(&client, guest(), log.to_str().unwrap())
        .await
        .expect("guest must run the vectors");

    let out = public_values.as_slice();
    assert_eq!(
        out.len(),
        cases.len() * 32,
        "expected one digest per vector, got {} bytes",
        out.len()
    );

    for (i, (tag, operand)) in cases.iter().enumerate() {
        let expected: [u8; 32] = Sha256::digest(operand).into();
        let got = &out[i * 32..(i + 1) * 32];
        assert_eq!(
            got,
            &expected[..],
            "vector {i} (tag {tag}) digest mismatch\n  operand {}\n  got      {}\n  expected {}",
            hex(operand),
            hex(got),
            hex(&expected)
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
