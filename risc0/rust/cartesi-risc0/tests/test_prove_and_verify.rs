use cartesi_risc0::{prove, verify, REPLAY_STEP_ELF, REPLAY_STEP_ID};
use std::fs;
use std::path::Path;

mod common;
use common::machine_rows;

#[test]
fn test_prove_and_verify() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    assert!(
        dir.exists(),
        "Fixtures directory does not exist: {}",
        dir.display()
    );

    let rows = machine_rows(dir);
    assert!(
        !rows.is_empty(),
        "no machine step-log rows in manifest: {}",
        dir.display()
    );

    for row in &rows {
        let path = dir.join(&row.name);
        eprintln!("Verifying {} (cycles={})", row.name, row.cycle_count);
        let log = fs::read(&path).expect("could not read step log");
        let receipt = prove(
            REPLAY_STEP_ELF,
            &row.root_before,
            &log,
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
    }
}

// A fake (dev-mode) receipt must be rejected unless the caller explicitly opts in:
// the receipt file is untrusted input, and the ambient RISC0_DEV_MODE variable alone
// must not be enough to accept it.
#[test]
fn test_verify_rejects_fake_receipt_without_opt_in() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    let row = machine_rows(dir)
        .into_iter()
        .next()
        .expect("no machine step-log rows in manifest");
    let log = fs::read(dir.join(&row.name)).expect("could not read step log");
    let receipt = prove(
        REPLAY_STEP_ELF,
        &row.root_before,
        &log,
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
