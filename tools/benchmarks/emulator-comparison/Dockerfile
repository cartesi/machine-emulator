ARG TOOLCHAIN_REPOSITORY=cartesi/toolchain
ARG TOOLCHAIN_VERSION=latest
FROM ${TOOLCHAIN_REPOSITORY}:${TOOLCHAIN_VERSION}

RUN apt update && \
	apt install -y --no-install-recommends \
		gccgo-riscv64-linux-gnu \
		openjdk-8-jdk-headless \
	&& \
	rm -rf /var/cache/apt/archives

COPY benchmarks benchmarks

# fasta
RUN riscv64-cartesi-linux-gnu-gcc -O2 -march=rv64ima -mabi=lp64 \
	-o benchmarks/fasta/c/fasta \
	benchmarks/fasta/c/fasta.c

RUN \
	export CC=riscv64-cartesi-linux-gnu-gcc; \
	export CXX=riscv64-cartesi-linux-gnu-g++; \
	export CFLAGS="-march=rv64ima -mabi=lp64"; \
	cd benchmarks/fasta/rust && \
	cargo +nightly build -Z build-std=std,core,alloc,panic_abort,proc_macro --target riscv64ima-cartesi-linux-gnu.json --release && \
	cp target/riscv64ima-cartesi-linux-gnu/release/rust_bench fasta

RUN javac benchmarks/fasta/java/fasta.java -source 1.8 -target 1.8

RUN riscv64-linux-gnu-gccgo -O2 \
	-o benchmarks/fasta/go/fasta \
	benchmarks/fasta/go/fasta.go && \
	riscv64-linux-gnu-strip benchmarks/fasta/go/fasta

# blake2b
RUN riscv64-cartesi-linux-gnu-gcc -O2 -march=rv64ima -mabi=lp64 \
	-o benchmarks/blake2b/c/blake2b \
	benchmarks/blake2b/c/blake2b.c \
	benchmarks/blake2b/c/main.c \
