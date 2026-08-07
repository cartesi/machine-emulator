use cartesi_risc0::MachineHash;
use cartesi_risc0::{try_prove, REPLAY_STEP_ELF};
use std::fs;
use std::path::Path;

// The big-machine (sha256) reject fixtures (tests/lua/record-adversarial-machine.lua) are
// structurally invalid logs. The guest must abort on each -- via zk_abort_with_msg, which
// carries the same message the C++ host throws -- rather than produce a valid receipt. This
// is the soundness statement: a malicious prover cannot get a proof for a forged log.

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

/// The substring the guest abort message must contain for each reject tag (the C++ throw
/// message, surfaced through zk_abort_with_msg).
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

    let text = fs::read_to_string(dir.join("_manifest.csv"))
        .unwrap_or_else(|e| panic!("failed to read reject manifest: {e}"));

    let mut checked = 0;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        // Schema: kind,name,expectError,hashFunction,cycle,before,after,reason,dataLength,data,revertRootHash
        let cols: Vec<&str> = line.split(',').collect();
        assert!(cols.len() >= 7, "malformed reject row: {line:?}");
        if cols[0] != "machine" {
            continue;
        }
        let name = cols[1];
        let tag = cols[2];
        let cycle: u64 = cols[4]
            .parse()
            .unwrap_or_else(|_| panic!("bad cycle: {:?}", cols[4]));
        let before = parse_hash(cols[5]);
        let after = parse_hash(cols[6]);
        let path = dir.join(name);

        eprintln!("Rejecting {name} (expect: {tag})");
        let err = try_prove(
            REPLAY_STEP_ELF,
            &before,
            path.to_str().unwrap(),
            cycle,
            &after,
        )
        .expect_err(&format!("guest ACCEPTED forged log {name} (tag {tag})"));
        let want = expected_message(tag);
        assert!(
            err.contains(want),
            "rejected {name} but message {err:?} lacks {want:?}"
        );
        checked += 1;
    }
    assert!(checked > 0, "no machine reject rows in {}", dir.display());
}

/// Layer-2: a valid log proven against a claim that disagrees with the journal must be
/// rejected host-side. Reuses a positive fixture with one perturbed argument.
#[test]
fn test_host_rejects_wrong_belief() {
    let dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));
    let text = fs::read_to_string(dir.join("_manifest.csv"))
        .unwrap_or_else(|e| panic!("failed to read manifest: {e}"));
    let (name, cycle, before, after) = text
        .lines()
        .skip(1)
        .find_map(|line| {
            let c: Vec<&str> = line.split(',').collect();
            if c.len() >= 7 && c[0] == "machine" {
                Some((
                    c[1].to_string(),
                    c[4].parse::<u64>().unwrap(),
                    parse_hash(c[5]),
                    parse_hash(c[6]),
                ))
            } else {
                None
            }
        })
        .expect("a machine row in the positive manifest");
    let path = dir.join(&name);
    let p = path.to_str().unwrap();

    let mut bad = before;
    bad[0] ^= 0xff;
    let e =
        try_prove(REPLAY_STEP_ELF, &bad, p, cycle, &after).expect_err("wrong root_before accepted");
    assert!(e.contains("root_hash_before mismatch"), "{e:?}");

    let e = try_prove(REPLAY_STEP_ELF, &before, p, cycle + 1, &after)
        .expect_err("wrong cycle accepted");
    assert!(e.contains("mcycle_count mismatch"), "{e:?}");

    let mut bad = after;
    bad[0] ^= 0xff;
    let e =
        try_prove(REPLAY_STEP_ELF, &before, p, cycle, &bad).expect_err("wrong root_after accepted");
    assert!(e.contains("root_hash_after mismatch"), "{e:?}");
}
