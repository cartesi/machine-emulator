// Each integration test is its own crate, so a field only one of them reads would be dead
// code in the other.
#![allow(dead_code)]

use cartesi_risc0::MachineHash;
use std::fs;
use std::path::Path;

// The fixture manifest tests/lua/cartesi/tests/step_log_manifest.lua writes next to each
// fixture set: one row per log, holding the arguments to pass and the outcome to expect.
// Its columns are recorded truth, captured from the LIVE machine, so they are an independent
// source of truth for what the prover commits to and the verifier checks.
//
// Schema: kind,name,expectError,hashFunction,requestedCycleCount,rootHashBefore,rootHashAfter,
// reason,dataLength,data,revertRootHash
const COL_KIND: usize = 0;
const COL_NAME: usize = 1;
const COL_EXPECT_ERROR: usize = 2;
const COL_CYCLE_COUNT: usize = 4;
const COL_ROOT_BEFORE: usize = 5;
const COL_ROOT_AFTER: usize = 6;

pub struct ManifestRow {
    pub kind: String,
    pub name: String,
    pub expect_error: String,
    pub cycle_count: u64,
    pub root_before: MachineHash,
    pub root_after: MachineHash,
}

fn parse_hash(s: &str) -> MachineHash {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(hex.len(), 64, "expected 32-byte hex hash, got {:?}", s);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .unwrap_or_else(|_| panic!("invalid hex in hash: {:?}", s));
    }
    out
}

pub fn read_manifest(dir: &Path) -> Vec<ManifestRow> {
    let path = dir.join("_manifest.csv");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read manifest {}: {}", path.display(), e));
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        assert!(
            cols.len() > COL_ROOT_AFTER,
            "malformed manifest row: {:?}",
            line
        );
        rows.push(ManifestRow {
            kind: cols[COL_KIND].to_string(),
            name: cols[COL_NAME].to_string(),
            expect_error: cols[COL_EXPECT_ERROR].to_string(),
            cycle_count: cols[COL_CYCLE_COUNT]
                .parse()
                .unwrap_or_else(|_| panic!("bad cycle count: {:?}", cols[COL_CYCLE_COUNT])),
            root_before: parse_hash(cols[COL_ROOT_BEFORE]),
            root_after: parse_hash(cols[COL_ROOT_AFTER]),
        });
    }
    rows
}

/// RISC0 replays the machine-level architecture step logs only.
pub fn machine_rows(dir: &Path) -> Vec<ManifestRow> {
    read_manifest(dir)
        .into_iter()
        .filter(|row| row.kind == "machine")
        .collect()
}
