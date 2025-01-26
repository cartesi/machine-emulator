use cartesi_risc0:: { prove, verify };
use cartesi_risc0_shared::MachineHash;
use std::fs;
use std::path::Path;

fn parse_hash(hex: &str) -> Result<MachineHash, String> {
    let bytes = hex::decode(hex).map_err(|_| format!("Invalid hex string: {}", hex))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32-byte hash, got {} bytes", bytes.len()));
    }
    let mut array = [0; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[test]
fn test_prove_and_verify() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join(file!())
        .parent().unwrap()
        .join("fixtures");
    
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
        if !file_name.starts_with("step-") && !file_name.ends_with(".log") {
            panic!("Unexpected file in fixtures directory: {}", file_name);
        }
        let parts: Vec<&str> = file_name.split('-').collect();
        if parts.len() < 5 {
            panic!("Invalid step log file name: {}", file_name);
        }
        let root_hash_before = parse_hash(parts[2]).expect("Failed to parse root hash before");
        let mcycle_count = parts[3].parse::<u64>()
            .expect(&format!("Invalid mcycle count in filename: {}", file_name));
        let root_hash_after = parse_hash(parts[4].strip_suffix(".log").unwrap_or(parts[4]))
            .expect("Failed to parse root hash after");

        eprintln!(
            "Verifying step file: {}\nStart hash: {:x?}, Cycle count: {}, End hash: {:x?}",
            file_name, root_hash_before, mcycle_count, root_hash_after
        );

        let receipt = prove(&root_hash_before, path.to_str().unwrap(), mcycle_count, &root_hash_after);
        verify(&receipt, &root_hash_before, mcycle_count, &root_hash_after);
        
        // TODO: Ensure that verify fails when the hash is wrong
        // let bad_hash : [u8; 32] = [0; 32];
        // verify(&receipt, &bad_hash, mcycle_count, &root_hash_after);
    }
}
