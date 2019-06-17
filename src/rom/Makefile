.PHONY: run-docker

run-docker:
	docker run -v `pwd`/example:/opt/riscv/rom_example -v `pwd`/src:/opt/riscv/rom -v `pwd`/test:/opt/riscv/test -v `pwd`/../:/opt/riscv/emulator -v `pwd`/dtc:/opt/riscv/dtc -w /opt/riscv/rom --rm -it cartesi/image-toolchain
