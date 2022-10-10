main: main.o opcode/riscv-opc.o opcode/riscv-dis.o
	g++ -o $@ $^

opcode/riscv-opc.o: opcode/riscv-opc.c
	gcc -I. -Ofast -march=native -Wall -c -o $@ $<

opcode/riscv-dis.o: opcode/riscv-dis.cpp
	g++ -I. -Ofast -march=native -Wall -pedantic -c -o $@ $<

main.o:	main.cpp
	g++ -I. -Ofast -march=native -Wall -pedantic -c -o $@ $<
