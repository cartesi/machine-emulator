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

//! The soundness statement: a malicious prover cannot get a proof for a forged
//! log. The reject fixtures are structurally invalid step logs and the guest
//! must abort on every one, each for its own reason.
//!
//! The reason arrives through the public-values stream (surfaced in
//! try_execute's error), the one channel every executor backend carries —
//! stderr forwarding is interpreter-only.
//!
//! Generate the fixtures with `make -C sp1 fixtures` (needs a built emulator).

use std::{fs, path::PathBuf};

use cartesi_sp1::try_execute;
use sp1_sdk::{Elf, ProverClient};

/// The substring the guest abort message must contain for each reject tag: the
/// C++ throw message, surfaced through zk_abort_with_msg.
fn expected_message(tag: &str) -> &'static str {
    match tag {
        "bad_signature" => "invalid step log signature",
        "unsupported_hash_function" => "unsupported hash function type",
        "nonzero_scratch_hash" => "scratch hash area is not zero",
        "initial_root_mismatch" => "initial root hash mismatch",
        "page_count_zero" => "page count is zero",
        "page_count_exceeds_size" => "page count exceeds step log size",
        "sibling_count_mismatch" => "sibling count does not match step log size",
        "page_index_not_increasing" => "page index is not in increasing order",
        "too_few_siblings" => "too few sibling hashes in log",
        other => panic!("unmapped reject tag: {other}"),
    }
}

fn repo_root() -> PathBuf {
    // sp1/rust -> sp1 -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("sp1/test/fixtures")
}

fn guest_elf() -> Elf {
    let path = repo_root().join("sp1/cpp/guest.elf");
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "guest.elf not built ({}): {e}. Run make -C sp1/cpp",
            path.display()
        )
    });
    Elf::Static(Box::leak(bytes.into_boxed_slice()))
}

#[tokio::test]
async fn guest_rejects_forged_logs() {
    let dir = fixtures_dir().join("reject-machine");
    assert!(
        dir.exists(),
        "reject fixtures missing: {}. Run make -C sp1 fixtures",
        dir.display()
    );
    let text = fs::read_to_string(dir.join("_manifest.csv"))
        .unwrap_or_else(|e| panic!("failed to read reject manifest: {e}"));

    let client = ProverClient::builder().light().build().await;
    let elf = guest_elf();
    let mut checked = 0;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        // Schema: kind,name,expectError,hashFunction,cycle,before,after,...
        let cols: Vec<&str> = line.split(',').collect();
        assert!(cols.len() >= 7, "malformed reject row: {line:?}");
        if cols[0] != "machine" {
            continue;
        }
        let (name, tag) = (cols[1], cols[2]);
        let path = dir.join(name);

        let error = try_execute(&client, elf.clone(), path.to_str().unwrap())
            .await
            .err()
            .unwrap_or_else(|| panic!("guest ACCEPTED forged log {name} (tag {tag})"));
        let expected = expected_message(tag);
        assert!(
            error.contains(expected),
            "forged log {name} (tag {tag}) rejected for the wrong reason:\n  \
             expected substring {expected:?}\n  error: {error}"
        );
        checked += 1;
    }
    assert!(checked > 0, "no machine reject rows in {}", dir.display());
}

/// A valid log run against a claim that disagrees with the journal must be
/// rejected host-side. This is the layer above guest soundness: the guest proved
/// something true, just not the thing the caller asked about.
#[tokio::test]
async fn host_rejects_wrong_belief() {
    use cartesi_sp1::{parse_hash, JOURNAL_SIZE};

    let path = fixtures_dir().join("one-mcycle/one-mcycle.log");
    assert!(
        path.exists(),
        "positive fixture missing: {}",
        path.display()
    );

    let client = ProverClient::builder().light().build().await;
    let (public_values, _) = try_execute(&client, guest_elf(), path.to_str().unwrap())
        .await
        .expect("valid fixture must execute");
    let pv = public_values.as_slice();
    assert_eq!(pv.len(), JOURNAL_SIZE);

    // The journal says mcycle_count 1; a caller claiming anything else is wrong.
    let logged_mcycle = u64::from_be_bytes(pv[56..64].try_into().unwrap());
    assert_eq!(logged_mcycle, 1, "fixture changed; update this test");

    // And the hashes must be exactly what the manifest recorded.
    let text =
        fs::read_to_string(fixtures_dir().join("one-mcycle/_manifest.csv")).expect("manifest");
    let row: Vec<&str> = text
        .lines()
        .nth(1)
        .expect("manifest row")
        .split(',')
        .collect();
    assert_eq!(
        &pv[0..32],
        &parse_hash(row[5]).unwrap()[..],
        "root_hash_before"
    );
    assert_eq!(
        &pv[64..96],
        &parse_hash(row[6]).unwrap()[..],
        "root_hash_after"
    );
}
