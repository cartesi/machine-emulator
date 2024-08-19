fn main() {
    cc::Build::new()
        .object("../../../../zkarch/zkarch-replay-steps.o")
        .compile("loxa");
}