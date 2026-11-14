# R1-O2-3: a failed `collect_mcycle_root_hashes` loses dirty marks, so the hash tree goes stale

## What is asserted

After `collect_mcycle_root_hashes` fails inside a running process because of a host allocation failure,
the machine's `get_root_hash()` must still equal the root of its actual contents. The test checks it
against the root rebuilt after `clear_hash_tree()`, and also checks `verify_hash_tree()`.

Requirement (THREAT_MODEL.md, R9): "The content hash must equal the root of the actual contents. This applies
to every cached, incremental, or persisted hash, after any sequence of documented operations. It includes
interrupted or failed updates [...] 'Interrupted or failed updates' means updates that fail inside a running
process, which then keeps using the machine." Section 4: "A host fault [...] may stop the honest operator, but
the emulator must never turn one into a wrong hash".

## How it works

- `guest.lua` assembles a small bare-metal guest, so no toolchain is needed. In M-mode it writes one Sv39
  leaf PTE (a 1 GiB identity gigapage, A=0 and D=0) into a page table at 0x80010000, sets satp, runs
  `sfence.vma` and mrets to S-mode. In S-mode it spins, and the page walk sets the PTE's A bit. Then it
  stores to 8000 distinct pages, and the first store makes the walk set the D bit. That D-bit update is a
  physical write to the page-table page that does not go through the write TLB. During collection, the only
  record of it is `context.dirty_pages` in `collect_mcycle_hashes_state_access`.
- `fail-new.cpp` is an LD_PRELOAD fault injector. It throws `std::bad_alloc`, as an allocator under a memory
  limit would, for any `operator new` request of at least 100000 bytes while an arm file exists. It is armed
  only during the faulty collection. The only such request inside that collection is the rehash of
  `context.dirty_pages` (131072 bytes) when it grows past its reservation of 4096 pages. The initial
  reservation (32 KiB and 64 KiB) is not affected.
- Control: the same guest is collected without a fault. The cached root equals the rebuilt root. Otherwise the
  test exits 2.
- Faulty run: the machine is run to mcycle 1000000, where the guest is spinning in S-mode with D clear. Then
  `collect_mcycle_root_hashes` runs with the injector armed. The test requires that the injected failure
  happened and that the PTE's D bit is now set. If either did not happen, the test exits 2. It then compares
  the hashes.

Defect: `machine::collect_mcycle_root_hashes` in `src/machine.cpp` catches only `machine_console_exception`
around `interpret_with_console`. It marks `context.dirty_pages` into the dirty page trees only after
`interpret` returns. Any other exception unwinds without those marks. Pages that were not in the write TLB stay
unmarked, and every later `update_hash_tree` skips them.

## Run

```sh
bugs/run.sh R1-O2-3        # needs g++ and the in-tree emulator build; about 3 s
```

## Expected output on audit/prt2 (exit 1)

```
control: no fault, cached root == rebuilt root 0xc458e981...
collect_mcycle_root_hashes failed as injected: std::bad_alloc
after the failure: mcycle=1000000 (started at 1000000), leaf PTE at 0x80010010 = 0x200000cf (D bit set)
page 0x80010000 (in RAM) is not marked dirty but is dirty
! FAILED!
get_root_hash() after the failure    0x53e7b6b5...
root rebuilt by clear_hash_tree()    0xd6fa527c...
verify_hash_tree() after the failure false
page-table page 0x80010000 node hash: cached 0x92407314..., rebuilt 0xde53c88e...
VIOLATED: R9: after collect_mcycle_root_hashes fails inside a running process (host allocation failure), ...
```

`verify_hash_tree` reports exactly the page-table page as dirty but not marked. Once the fix is in, for
example by marking `context.dirty_pages` when unwinding, the two roots agree and the test exits 0.

A side observation that is not asserted: after the failure, `mcycle` is still at its starting value while the
other registers and memory have advanced. This is because the interpreter writes mcycle only when it leaves
its loop.
