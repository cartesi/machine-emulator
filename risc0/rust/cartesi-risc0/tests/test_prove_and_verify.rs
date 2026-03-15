use cartesi_risc0::{prove, verify, REPLAY_STEP_ELF, REPLAY_STEP_ID};
use cartesi_risc0::MachineHash;
use std::fs;
use std::path::Path;
use std::io::Read;

fn read_step_log_header(path: &str) -> Result<(MachineHash, u64, MachineHash), String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Failed to open step log: {}", e))?;

    let mut header = [0u8; 72];
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read step log header: {}", e))?;

    let mut root_hash_before = [0u8; 32];
    root_hash_before.copy_from_slice(&header[0..32]);

    let mcycle_count = u64::from_le_bytes([
        header[32], header[33], header[34], header[35],
        header[36], header[37], header[38], header[39],
    ]);

    let mut root_hash_after = [0u8; 32];
    root_hash_after.copy_from_slice(&header[40..72]);

    Ok((root_hash_before, mcycle_count, root_hash_after))
}

#[test]
fn test_prove_and_verify() {
    let fixtures_dir = Path::new(env!("CARTESI_STEP_LOGS_PATH"));

    assert!(fixtures_dir.exists(), "Fixtures directory does not exist: {}", fixtures_dir.display());

    let dir_entries = fs::read_dir(&fixtures_dir)
        .expect("Failed to read directory")
        .collect::<Vec<_>>();

    if dir_entries.is_empty() {
        panic!("No step log files found in directory: {}", fixtures_dir.display());
    }

    for entry in dir_entries {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_str().unwrap();

        // Skip files that don't match the step log pattern
        if !file_name.starts_with("step-") || !file_name.ends_with(".log") {
            continue;
        }

        let (root_hash_before, mcycle_count, root_hash_after) =
            read_step_log_header(path.to_str().unwrap())
                .expect(&format!("Failed to read step log header from {}", file_name));

        eprintln!(
            "Verifying step file: {}\nStart hash: {:02x?}, Cycle count: {}, End hash: {:02x?}",
            file_name, root_hash_before, mcycle_count, root_hash_after
        );

        let receipt = prove(REPLAY_STEP_ELF, &root_hash_before, path.to_str().unwrap(), mcycle_count, &root_hash_after);
        verify(&REPLAY_STEP_ID, &receipt, &root_hash_before, mcycle_count, &root_hash_after);
    }
}
