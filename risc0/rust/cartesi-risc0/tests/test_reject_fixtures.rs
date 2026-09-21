use cartesi_risc0::{try_prove, REPLAY_STEP_ELF};
use std::fs;
use std::path::Path;

mod common;
use common::machine_rows;

// The big-machine (sha256) reject fixtures (tests/lua/record-adversarial-machine.lua) are
// structurally invalid logs. The guest must abort on each -- via zk_abort_with_msg, which
// carries the same message the C++ host throws -- rather than produce a valid receipt. This
// is the soundness statement: a malicious prover cannot get a proof for a forged log.

/// The substring the guest abort message must contain for each reject tag (the C++ throw
/// message, surfaced through zk_abort_with_msg).
fn expected_message(tag: &str) -> &'static str {
    match tag {
        "bad_signature" => "invalid step log signature",
        "unsupported_hash_function" => "unsupported hash function type",
        "nonzero_scratch_hash" => "scratch hash area is not zero",
        "page_count_zero" => "page count is zero",
        "page_count_exceeds_size" => "page count exceeds step log size",
        "sibling_count_mismatch" => "sibling count does not match step log size",
        "page_index_not_increasing" => "page index is not in increasing order",
        "too_few_siblings" => "too few sibling hashes in log",
        other => panic!("unmapped reject tag: {other}"),
    }
}

#[test]
fn test_guest_rejects_forged_logs() {
    // reject-machine/ sits next to the positive cartesi-machine-tests/ fixtures.
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"))
        .parent()
        .expect("fixtures parent")
        .join("reject-machine");
    assert!(
        dir.exists(),
        "reject fixtures dir does not exist: {}",
        dir.display()
    );

    let rows = machine_rows(&dir);
    assert!(
        !rows.is_empty(),
        "no machine reject rows in {}",
        dir.display()
    );

    for row in &rows {
        let (name, tag) = (&row.name, &row.expect_error);
        let log = fs::read(dir.join(name)).expect("could not read step log");

        eprintln!("Rejecting {name} (expect: {tag})");
        let err = try_prove(
            REPLAY_STEP_ELF,
            &row.root_before,
            &log,
            row.cycle_count,
            &row.root_after,
        )
        .expect_err(&format!("guest ACCEPTED forged log {name} (tag {tag})"));
        let want = expected_message(tag);
        assert!(
            err.contains(want),
            "rejected {name} but message {err:?} lacks {want:?}"
        );
    }
}

/// A valid log proven against a claim that disagrees with the journal must be
/// rejected host-side. Reuses a positive fixture with one perturbed argument.
#[test]
fn test_host_rejects_wrong_belief() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    let row = machine_rows(dir)
        .into_iter()
        .next()
        .expect("a machine row in the positive manifest");
    let (cycle, before, after) = (row.cycle_count, row.root_before, row.root_after);
    let log = fs::read(dir.join(&row.name)).expect("could not read step log");

    let mut bad = before;
    bad[0] ^= 0xff;
    let e = try_prove(REPLAY_STEP_ELF, &bad, &log, cycle, &after)
        .expect_err("wrong root_before accepted");
    assert!(e.contains("root_hash_before mismatch"), "{e:?}");

    // A wrong cycle count replays a different transition. Probe with fewer cycles: the
    // replay stops at an intermediate state whose hash cannot match the claimed root
    // after. (More cycles would be no probe at all: the machine halts at the recorded
    // count, and running longer through the halt fixed point is the same transition.)
    assert!(
        cycle > 1,
        "need a multi-cycle fixture to probe a wrong count"
    );
    let e = try_prove(REPLAY_STEP_ELF, &before, &log, cycle - 1, &after)
        .expect_err("wrong cycle accepted");
    assert!(e.contains("root_hash_after mismatch"), "{e:?}");

    let mut bad = after;
    bad[0] ^= 0xff;
    let e = try_prove(REPLAY_STEP_ELF, &before, &log, cycle, &bad)
        .expect_err("wrong root_after accepted");
    assert!(e.contains("root_hash_after mismatch"), "{e:?}");
}
