use std::env;
use memmap2::MmapOptions;
use std::fs::{File};
use methods::{
    TESTE1_ELF, TESTE1_ID
};
use risc0_zkvm::{
        default_prover, 
        ExecutorEnv };

  
  /*
    How to run this:
    1) create a step log 
    cartesi-machine.lua  --max-mcycle=0 --log-step=1,/tmp/step.bin 
    Logging step of 1 cycles to /tmp/step.bin
    0: 5b4d6e46f7c024a1c108dcd2d7c174ec8ed2259a7ca53e362c611c2476791cb0
    1: f66a12a3601c991025f7658226220f8346365f98958f5859a3add8954c1b1dd4

    2) pass hashes, log file and mcycle_count to the host
    cargo run 2ce13ae92f9a25102ed5cc67e97c5de69921f4e66400f3710d7938e33e027ce1 /tmp/step.bin 1 5efccf3096a2f4d780d91cd8097481d08f5084ea6f077e001334aadccc42f0d7
   */
  fn main() {
    fn parse_hash(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex).expect("Invalid hex string");
        let mut array = [0; 32];
        array.copy_from_slice(&bytes);
        array
    }
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <root_hash_before> <log_file_path> <mcycle_count> <root_hash_after>", args[0]);
        std::process::exit(1);
    }
    let root_hash_before = parse_hash(&args[1]);
    let log_file_path = &args[2];
    let mcycle_count: u64 = args[3].parse().expect("Invalid step count");
    let root_hash_after = parse_hash(&args[4]);
    assert_eq!(root_hash_before.len(), 32);
    assert_eq!(root_hash_after.len(), 32);
    // mmap the step log file
    let log_file = File::open(log_file_path).expect("Could not open log file");
    let log_file_len = log_file.metadata().expect("Could not get metadata").len();
    let log_file = unsafe {
        MmapOptions::new()
            .len(log_file_len as usize)
            .map(&log_file)
            .expect("Could not memory map log file")
    };
    println!("original log_file_len: {:?}", log_file_len);
    let mut builder = ExecutorEnv::builder();
    builder.write(&mcycle_count).unwrap();
    builder.write(&root_hash_before).unwrap();
    builder.write(&root_hash_after).unwrap();
    builder.write(&log_file_len).unwrap();
    for i in (0..log_file_len).step_by(1) {
        builder.write(&log_file[i as usize]).unwrap();
    }
    let env = builder.build().unwrap();
    let prover = default_prover();
    println!("host: prover created");   
    let receipt = prover
        .prove(env, TESTE1_ELF)
        .unwrap();
    println!("host: proof generated");    
    let result:u64 = receipt.journal.decode().unwrap();
    println!("host: zkarch_replay_steps result: {:?}", result);
    receipt
        .verify(TESTE1_ID)
        .unwrap();
    println!("host: proof verified");
}
    