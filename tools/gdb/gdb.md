# How to use GDB

This is a documentation on how to use GDB to debug privileged code with the Cartesi machine emulator.

## How to debug with GDB

1. Add `source <EMULATOR_PATH>/tools/gdb/gdbinit` to your `$HOME/.gdbinit` file to add custom cartesi-machine to your GDB, remember to replace `<EMULATOR_PATH>` with your emulator path.
2. Run `cartesi-machine --gdb` in a terminal, the machine will start stopped at cycle 0, waiting for a connection from GDB.
3. Run `riscv64-cartesi-linux-gnu-gdb -ex "set arch riscv:rv64" -ex "target remote 127.0.0.1:1234"` in another terminal. You can use any GDB, like the one provided in your Linux distribution, as long it is compiled with RISC-V support.
4. Step machine cycles with `stepc` commands or use other GDB commands.

## How to get debug information to work

1. You need to compile your kernel or test that you would like to debug with
debug information into a binary ELF file (using `.bin` will not work).
2. Connect GDB with `riscv64-cartesi-linux-gnu-gdb -ex "set arch riscv:rv64" -ex "target remote 127.0.0.1:1234" <elf>` where `<elf>` is your kernel or test ELF file compiled with debug information.
3. To view C/C++ code, make sure you run GDB client in a directory that is able to access the source files relative to the ELF binary being debugged.

## GDB commands

The following is a list of all custom GDB commands contained in `tools/gdb/gdbinit`:

- `cycles` retrieve machine cycles
- `stepc [n]` step 1 or `n` mcycles
- `stepu <n>` step until mcycle
- `csr <name>` get CSR value, .e.g. `csr mcycle`
- `csr <name>=1` set CSR value, .e.g. `csr mcycle=0`
- `hash` print machine hash in the current state
- `store <dir>` store machine state into `dir`
- `lua "<code>"` execute an arbitrary machine Lua code, e.g. `lua "print(machine:read_pc())"`
- `breakpc <address>` toggle a hardware breakpoint at PC

Aliases:
- `sc` alias for `stepc`
- `su` alias for `stepu`
- `bpc` alias for `breakpc`

## Tips

- You can step cycle by cycle quickly by using the command `sc` and pressing enter multiple times.
- You can step multiple cycles quickly by using the command `sc <n>` and pressing enter multiple times.
- Use `layout asm` to open a window to see the current instructions being executed.
- Use `layout regs` to open a window to see all registers values and highlight register changes.
- Use `break *0x2000` to break at a specific PC (`0x2000` in this case) and then `continue` to let the machine run until reaching that PC.
- Use `breakpc 0x2000` to break at a specific PC even when the memory range is not available yet, and then `continue` to let the machine run until reaching that PC.
- If you need to place breakpoints after kernel boot, placing it at the session start and letting it continue can be very slow. Prefer to use `stepu <n>` where `<n>` is a number of cycles large enough to let the kernel boot first, and just later after boot place your breakpoint and let it continue.

## Improving debugging experience

You could add the following lines to `$HOME/.gdbinit` to improve your debugging session experience.

```
# make gdb more quiet
set verbose off
set confirm off

# save command history
set history filename ~/.gdb_history
set history save

# cartesi machine debugging commands
source <EMULATOR_PATH>/tools/gdb/gdbinit
```

Remember to replace `<EMULATOR_PATH>` with your emulator path.
