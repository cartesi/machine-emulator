extra.bin: extra/htifpoweroff
	genext2fs -i 512 -b 8192 -d extra extra.bin

extra/htifpoweroff: htifpoweroff.c
	riscv64-unknown-linux-gnu-gcc -O2 -o extra/htifpoweroff htifpoweroff.c
