// fn main() {
//     cc::Build::new()
//         .object("../../../../zkarch/zkarch-replay-steps.o")
//         .compile("loxa");
// }

fn main() {
    const OBJ_PATH: &str = "../../../../zkarch/zkarch-replay-steps.o";

    println!("cargo:rerun-if-changed={}", OBJ_PATH);
    cc::Build::new()
        .object(OBJ_PATH)
        .compile("cartesi_zkarch_replay_steps");
}
