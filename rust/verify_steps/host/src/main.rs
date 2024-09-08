use std::fs::{File};
use std::io::Read;
use methods::{
    TESTE1_ELF, TESTE1_ID
};
use risc0_zkvm::{
        sha::{Digest, Impl, Sha256},
        default_prover, 
        ExecutorEnv };

fn load_page_data(file_path: &str) -> (Vec<u8>, u32) {
    let mut file = File::open(file_path).expect("Could not open file");
    let mut buffer = [0; 4];
    file.read(&mut buffer).expect("Could not read file contents");
    let page_count = u32::from_le_bytes(buffer);
    let mut data = vec![0; (page_count * (8+4096)) as usize];
    file.read(&mut data).expect("Could not read file contents");
    (data, page_count)
}


// run this command to run the 15 cycles used by this test
 // cartesi-machine.lua  --max-mcycle=0 --log-steps=15,/tmp
fn main() {
    let step_count: u64 = 1; // number of steps to replay
    let (data_before, page_count_before) = load_page_data("/tmp/pages-before");
    let hash_before = Impl::hash_bytes(&data_before);
    println!("host: hash before: {:?}", hash_before);
    let (data_after, page_count_after) = load_page_data("/tmp/pages-after");
    assert_eq!(page_count_before, page_count_after);
    let hash_after = Impl::hash_bytes(&data_after);
    println!("host: hash after: {:?}", hash_after);
    
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    
    let mut builder = ExecutorEnv::builder();
    let data_size: u32 = data_before.len() as u32;
    builder.write(&step_count).unwrap();
    builder.write(&page_count_before).unwrap();
    for i in (0..data_size).step_by(1) {
        builder.write(&data_before[i as usize]).unwrap();
    }
    let env = builder.build().unwrap();
    let prover = default_prover();
    let receipt = prover
        .prove(env, TESTE1_ELF)
        .unwrap();
    
    let hash_after_guest:Digest = receipt.journal.decode().unwrap();
    println!("host: hash after guest: {:?}", hash_after_guest);
    assert_eq!(hash_after_guest, *hash_after);
    receipt
        .verify(TESTE1_ID)
        .unwrap();
}
