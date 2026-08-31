use cartesi_risc0::MachineHash;
use cartesi_risc0::{prove, verify, REPLAY_STEP_ELF, REPLAY_STEP_ID};
use std::fs;
use std::path::Path;

// Expected hashes come from the _manifest.csv written by the recorder from the
// LIVE machine - an independent source of truth. The log itself carries no
// claims, so these rows are the claims the prover commits to and the
// verification checks against.
struct ManifestRow {
    kind: String,
    name: String,
    cycle_count: u64,
    root_before: MachineHash,
    root_after: MachineHash,
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

fn read_manifest(dir: &Path) -> Vec<ManifestRow> {
    let path = dir.join("_manifest.csv");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read manifest {}: {}", path.display(), e));
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        // Schema: kind,name,expectError,hashFunction,requestedCycleCount,rootHashBefore,rootHashAfter,
        // reason,dataLength,data,revertRootHash
        let cols: Vec<&str> = line.split(',').collect();
        assert!(cols.len() >= 7, "malformed manifest row: {:?}", line);
        rows.push(ManifestRow {
            kind: cols[0].to_string(),
            name: cols[1].to_string(),
            cycle_count: cols[4]
                .parse()
                .unwrap_or_else(|_| panic!("bad cycle count: {:?}", cols[4])),
            root_before: parse_hash(cols[5]),
            root_after: parse_hash(cols[6]),
        });
    }
    rows
}

#[test]
fn test_prove_and_verify() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    assert!(
        dir.exists(),
        "Fixtures directory does not exist: {}",
        dir.display()
    );

    let rows = read_manifest(dir);
    assert!(!rows.is_empty(), "manifest has no rows: {}", dir.display());

    let mut replayed = 0;
    for row in &rows {
        // RISC0 replays the machine-level architecture step logs only.
        if row.kind != "machine" {
            continue;
        }
        let path = dir.join(&row.name);
        eprintln!("Verifying {} (cycles={})", row.name, row.cycle_count);
        let receipt = prove(
            REPLAY_STEP_ELF,
            &row.root_before,
            path.to_str().unwrap(),
            row.cycle_count,
            &row.root_after,
        );
        verify(
            &REPLAY_STEP_ID,
            &receipt,
            &row.root_before,
            row.cycle_count,
            &row.root_after,
            true, // tests prove under RISC0_DEV_MODE, so receipts are fake
        );
        replayed += 1;
    }
    assert!(
        replayed > 0,
        "no machine step-log rows in manifest: {}",
        dir.display()
    );
}

// A fake (dev-mode) receipt must be rejected unless the caller explicitly opts in:
// the receipt file is untrusted input, and the ambient RISC0_DEV_MODE variable alone
// must not be enough to accept it.
#[test]
fn test_verify_rejects_fake_receipt_without_opt_in() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    let row = read_manifest(dir)
        .into_iter()
        .find(|r| r.kind == "machine")
        .expect("no machine step-log rows in manifest");
    let path = dir.join(&row.name);
    let receipt = prove(
        REPLAY_STEP_ELF,
        &row.root_before,
        path.to_str().unwrap(),
        row.cycle_count,
        &row.root_after,
    );
    if cartesi_risc0::receipt_kind(&receipt) != "fake" {
        return; // real prover in use; nothing to reject
    }
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify(
            &REPLAY_STEP_ID,
            &receipt,
            &row.root_before,
            row.cycle_count,
            &row.root_after,
            false,
        );
    }));
    assert!(rejected.is_err(), "fake receipt accepted without opt-in");
}
