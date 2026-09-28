// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
pragma solidity ^0.8.30;

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {HashTree} from "src/HashTree.sol";
import {StepLog} from "src/StepLog.sol";

/// Read/write accessors over a decoded step log. The transpiled uarch interpreter
/// calls these methods; names match `machine-emulator/src/uarch-solidity-compat.hpp`,
/// semantics mirror `replay-step-state-access.hpp`.
library StateAccess {
    error UnalignedWordAccess(uint64 paddr);
    error UarchXRegisterOutOfRange(uint8 reg);
    error WriteMemoryNodeWrongSize(uint32 expectedLog2Size, uint64 nodeLog2Size);
    error ResetUarchWrongSize(uint64 nodeLog2Size);
    error Uint32Log2OfZero();
    /// Wraps the message from a C++ THROW(...) call site (transpiled via throwRuntimeError).
    error RuntimeError(string message);

    // Wire format stores multi-byte integers little-endian; the EVM word format
    // is big-endian. readWord / writeWord internalise the swap.

    function readWord(StepLog.Context memory ctx, uint64 paddr) internal pure returns (uint64) {
        if (paddr & 0x7 != 0) revert UnalignedWordAccess(paddr);
        if (
            paddr >= EmulatorConstants.UARCH_HALT_ADDR
                && paddr < EmulatorConstants.UARCH_REGISTER_END_ADDR
        ) {
            return StepLog.readUarchWord(ctx, (paddr - EmulatorConstants.UARCH_HALT_ADDR) / 8);
        }
        if (
            (paddr & ~EmulatorConstants.PAGE_OFFSET_MASK)
                == EmulatorConstants.AR_SHADOW_UARCH_STATE_START
        ) {
            StepLog.flushUarchRegisters(ctx);
        }
        // Inline twin of locatePage's hit path: avoid helper call frames on every
        // instruction fetch/load. Misses still use the shared checked search.
        uint256[61] memory cache = ctx.pageLookupCache;
        uint64 idx = paddr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint256 cacheSlot = uint256(idx) % cache.length;
        uint256 cached;
        // Modulo the fixed array length guarantees cacheSlot is in 0..60.
        assembly ("memory-safe") {
            cached := mload(add(cache, shl(5, cacheSlot)))
        }
        uint256 lo;
        unchecked {
            if (cached >> 6 == uint256(idx) + 1) {
                lo = cached & 0x3f;
            } else {
                lo = StepLog.resolvePageMiss(ctx, idx, cacheSlot);
            }
        }
        bytes memory pd = ctx.pageData;
        uint256 pageSize = EmulatorConstants.PAGE_SIZE;
        uint256 pageMask = EmulatorConstants.PAGE_OFFSET_MASK;
        uint64 value;
        // Inline swapBytes64 twin: its callee size exceeds solc's hot-path inlining budget.
        // Decoded cache positions are in 0..63; the aligned word fits its page.
        assembly ("memory-safe") {
            let ptr := add(add(pd, 32), add(mul(lo, pageSize), and(paddr, pageMask)))
            let v := shr(192, mload(ptr))
            v := or(and(shr(8, v), 0x00ff00ff00ff00ff), and(shl(8, v), 0xff00ff00ff00ff00))
            v := or(and(shr(16, v), 0x0000ffff0000ffff), and(shl(16, v), 0xffff0000ffff0000))
            value := and(or(shr(32, v), shl(32, v)), 0xffffffffffffffff)
        }
        return value;
    }

    function writeWord(StepLog.Context memory ctx, uint64 paddr, uint64 val) internal pure {
        if (paddr & 0x7 != 0) revert UnalignedWordAccess(paddr);
        if (
            paddr >= EmulatorConstants.UARCH_HALT_ADDR
                && paddr < EmulatorConstants.UARCH_REGISTER_END_ADDR
        ) {
            StepLog.writeUarchWord(ctx, (paddr - EmulatorConstants.UARCH_HALT_ADDR) / 8, val);
            return;
        }
        if (
            (paddr & ~EmulatorConstants.PAGE_OFFSET_MASK)
                == EmulatorConstants.AR_SHADOW_UARCH_STATE_START
        ) {
            StepLog.flushUarchRegisters(ctx);
            ctx.uarchShadowPtr = 0;
        }
        // Inline twin of findPageForWrite's cache hit and hash invalidation.
        // Keep the readable helper as a reference; misses use the same checked search.
        uint256[61] memory cache = ctx.pageLookupCache;
        uint64 idx = paddr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint256 cacheSlot = uint256(idx) % cache.length;
        uint256 cached;
        // Modulo the fixed array length guarantees cacheSlot is in 0..60.
        assembly ("memory-safe") {
            cached := mload(add(cache, shl(5, cacheSlot)))
        }
        uint256 lo;
        unchecked {
            if (cached >> 6 == uint256(idx) + 1) {
                lo = cached & 0x3f;
            } else {
                lo = StepLog.resolvePageMiss(ctx, idx, cacheSlot);
            }
        }
        bytes memory pd = ctx.pageData;
        bytes32[] memory hashes = ctx.pageHashes;
        uint256 pageSize = EmulatorConstants.PAGE_SIZE;
        uint256 pageMask = EmulatorConstants.PAGE_OFFSET_MASK;
        uint256 ptr;
        // A matching tag or successful miss resolves an existing page. decode
        // caps positions at 63 and sizes both arrays equally; the aligned word fits.
        assembly ("memory-safe") {
            mstore(add(add(hashes, 32), shl(5, lo)), 0)
            ptr := add(add(pd, 32), add(mul(lo, pageSize), and(paddr, pageMask)))
        }
        StepLog.writeLE64Memory(ptr, val);
    }

    function readHalt(StepLog.Context memory ctx) internal pure returns (uint64) {
        return StepLog.readUarchWord(ctx, EmulatorConstants.UARCH_HALT_WORD_INDEX);
    }

    function writeHalt(StepLog.Context memory ctx, uint64 val) internal pure {
        StepLog.writeUarchWord(ctx, EmulatorConstants.UARCH_HALT_WORD_INDEX, val);
    }

    function readCycle(StepLog.Context memory ctx) internal pure returns (uint64) {
        return StepLog.readUarchWord(ctx, EmulatorConstants.UARCH_CYCLE_WORD_INDEX);
    }

    function writeCycle(StepLog.Context memory ctx, uint64 val) internal pure {
        StepLog.writeUarchWord(ctx, EmulatorConstants.UARCH_CYCLE_WORD_INDEX, val);
    }

    function readPc(StepLog.Context memory ctx) internal pure returns (uint64) {
        return StepLog.readUarchWord(ctx, EmulatorConstants.UARCH_PC_WORD_INDEX);
    }

    function writePc(StepLog.Context memory ctx, uint64 val) internal pure {
        if (ctx.uarchShadowPtr == 0) StepLog.loadUarchRegisters(ctx);
        ctx.uarchRegisters[EmulatorConstants.UARCH_PC_WORD_INDEX] = val;
        // Inline writeUarchWord twin: retain first-pending-write invalidation.
        if (!ctx.uarchRegistersDirty) {
            ctx.uarchRegistersDirty = true;
            ctx.pageHashes[ctx.uarchShadowPageIndex] = bytes32(0);
        }
    }

    function readX(StepLog.Context memory ctx, uint8 reg) internal pure returns (uint64) {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) revert UarchXRegisterOutOfRange(reg);
        if (ctx.uarchShadowPtr == 0) StepLog.loadUarchRegisters(ctx);
        uint64[35] memory registers = ctx.uarchRegisters;
        uint256 firstX = EmulatorConstants.UARCH_X_WORD_INDEX;
        uint64 value;
        // Inline readUarchWord twin: reg < 32 makes 3 + reg fit the 35-word array.
        // Keep the warm path here to avoid helper frames on every register access.
        assembly ("memory-safe") {
            value := mload(add(registers, shl(5, add(firstX, and(reg, 0xff)))))
        }
        return value;
    }

    function writeX(StepLog.Context memory ctx, uint8 reg, uint64 val) internal pure {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) revert UarchXRegisterOutOfRange(reg);
        if (ctx.uarchShadowPtr == 0) StepLog.loadUarchRegisters(ctx);
        uint64[35] memory registers = ctx.uarchRegisters;
        uint256 firstX = EmulatorConstants.UARCH_X_WORD_INDEX;
        // Inline writeUarchWord twin: reg < 32 makes 3 + reg fit the 35-word array.
        assembly ("memory-safe") {
            mstore(
                add(registers, shl(5, add(firstX, and(reg, 0xff)))), and(val, 0xffffffffffffffff)
            )
        }
        // The hash stays invalid while writes are pending; hashing flushes first.
        if (!ctx.uarchRegistersDirty) {
            ctx.uarchRegistersDirty = true;
            ctx.pageHashes[ctx.uarchShadowPageIndex] = bytes32(0);
        }
    }

    /// Returns bool to match the transpiled body's `!readIflagsY(a)` pattern.
    function readIflagsY(StepLog.Context memory ctx) internal pure returns (bool) {
        return readWord(ctx, EmulatorConstants.IFLAGS_Y_ADDRESS) != 0;
    }

    function writeIflagsY(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.IFLAGS_Y_ADDRESS, val);
    }

    function writeHtifFromhost(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.HTIF_FROMHOST_ADDR, val);
    }

    function readHtifTohost(StepLog.Context memory ctx) internal pure returns (uint64) {
        return readWord(ctx, EmulatorConstants.HTIF_TOHOST_ADDRESS);
    }

    function readMcycle(StepLog.Context memory ctx) internal pure returns (uint64) {
        return readWord(ctx, EmulatorConstants.MCYCLE_ADDRESS);
    }

    function writeImcyclemax(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.IMCYCLEMAX_ADDRESS, val);
    }

    // The revert root hash occupies a full 32-byte shadow slot, stored raw (no byte swap) so the
    // page bytes match the C++/RISC0 replayers. The slot ends exactly at the page boundary.
    function writeRevertRootHash(StepLog.Context memory ctx, bytes32 h) internal pure {
        uint256 ptr =
            StepLog.findPageForWrite(ctx, EmulatorConstants.AR_SHADOW_REVERT_ROOT_HASH_START);
        assembly ("memory-safe") {
            mstore(ptr, h)
        }
    }

    function readRevertRootHash(StepLog.Context memory ctx) internal pure returns (bytes32 h) {
        uint256 ptr = StepLog.findPage(ctx, EmulatorConstants.AR_SHADOW_REVERT_ROOT_HASH_START);
        assembly ("memory-safe") {
            h := mload(ptr)
        }
    }

    // Records that the reset reverted the canonical state on a rejected input. The page model recomputes
    // the tree from the pages (which reflect the pristine uarch), so the revert root hash is carried on
    // the context and returned by Verify.verifyReset as the obtained root.
    function revertState(StepLog.Context memory ctx) internal pure {
        ctx.reverted = true;
        ctx.revertedRootHash = readRevertRootHash(ctx);
    }

    // True when the tohost word holds a manual yield with the given reason.
    function isYieldedManualWith(uint64 tohost, uint64 yieldReason) internal pure returns (bool) {
        uint64 dev = uint64ShiftRight(
            tohost & EmulatorConstants.HTIF_DEV_MASK, EmulatorConstants.HTIF_DEV_SHIFT
        );
        uint64 cmd = uint64ShiftRight(
            tohost & EmulatorConstants.HTIF_CMD_MASK, EmulatorConstants.HTIF_CMD_SHIFT
        );
        uint64 reason = uint64ShiftRight(
            tohost & EmulatorConstants.HTIF_REASON_MASK, EmulatorConstants.HTIF_REASON_SHIFT
        );
        return dev == EmulatorConstants.HTIF_DEV_YIELD
            && cmd == EmulatorConstants.HTIF_YIELD_CMD_MANUAL && reason == yieldReason;
    }

    function writeMemoryWithPadding(
        StepLog.Context memory ctx,
        uint64 paddr,
        bytes calldata data,
        uint64 dataLength,
        uint32 writeLengthLog2Size
    ) internal pure {
        if (writeLengthLog2Size <= EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE) {
            // Mirrors copy_n + fill_n in do_write_memory_with_padding (replay-step-state-access.hpp).
            uint256 dstPtr = StepLog.findPageForWrite(ctx, paddr);
            uint256 len = uint256(dataLength);
            uint256 padLen = (uint256(1) << writeLengthLog2Size) - len;
            assembly ("memory-safe") {
                calldatacopy(dstPtr, data.offset, len)
                // calldatacopy from offset >= calldatasize() zero-fills (EVM rule), giving free zero padding.
                if padLen { calldatacopy(add(dstPtr, len), calldatasize(), padLen) }
            }
            return;
        }
        // Supra-page: the write spans more than one page, so the recorder did not
        // include the affected pages; it summarised them as a single node entry.
        // findNode returns a reference into ctx.nodes, so the slot write lands in the context.
        StepLog.NodeEntry memory n = StepLog.findNode(ctx, paddr);
        if (uint32(n.log2Size) != writeLengthLog2Size) {
            revert WriteMemoryNodeWrongSize(writeLengthLog2Size, n.log2Size);
        }
        n.hash = HashTree.merkleTreeHashPadded(data, uint8(writeLengthLog2Size));
    }

    /// Mirrors do_reset_uarch in uarch-replay-step-state-access.hpp.
    function resetState(StepLog.Context memory ctx) internal pure {
        StepLog.NodeEntry memory n = StepLog.findNode(ctx, EmulatorConstants.UARCH_STATE_START_ADDR);
        if (n.log2Size != EmulatorConstants.UARCH_STATE_LOG2_SIZE) {
            revert ResetUarchWrongSize(n.log2Size);
        }
        n.hash = EmulatorConstants.UARCH_PRISTINE_STATE_HASH;
    }

    // ECALL helpers - match the no-op / write shape of the C++ replay accessor.

    /// No-op in replay; mirrors do_putchar (returns false, write goes nowhere).
    function putCharECALL(StepLog.Context memory, uint8) internal pure {}

    /// Slot layout (per shadow_tlb_slot in machine-emulator/src/shadow-tlb.hpp):
    ///   offset  0: vaddr_page (uint64)
    ///   offset  8: vp_offset  (uint64)
    ///   offset 16: pma_index  (uint64)
    ///   offset 24: zero_padding_ (always 0)
    function writeTlbECALL(
        StepLog.Context memory ctx,
        uint64 setIndex,
        uint64 slotIndex,
        uint64 vaddrPage,
        uint64 vpOffset,
        uint64 pmaIndex
    ) internal pure {
        uint64 slotAddr;
        // Both generated ECALL handlers bound setIndex < 3 and slotIndex < 256.
        // Slot addresses are 0x1000..0x6fe0, so no uint64 operation can overflow.
        unchecked {
            slotAddr = EmulatorConstants.AR_SHADOW_TLB_START
                + setIndex * EmulatorConstants.SHADOW_TLB_SET_LENGTH
                + slotIndex * EmulatorConstants.SHADOW_TLB_SLOT_SIZE;
        }

        // A 32-byte-aligned slot fits wholly within one witnessed page. Locate
        // and invalidate it once, then store the three little-endian fields and
        // eight bytes of zero padding together.
        if (
            (slotAddr & ~EmulatorConstants.PAGE_OFFSET_MASK)
                == EmulatorConstants.AR_SHADOW_UARCH_STATE_START
        ) {
            StepLog.flushUarchRegisters(ctx);
            ctx.uarchShadowPtr = 0;
        }
        // Inline twin of findPageForWrite, as in writeWord. Validated TLB slots
        // never alias the uarch shadow page; keep the helper's flush/drop semantics.
        uint256[61] memory cache = ctx.pageLookupCache;
        uint64 idx = slotAddr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint256 cacheSlot = uint256(idx) % cache.length;
        uint256 cached;
        // Modulo the fixed array length guarantees cacheSlot is in 0..60.
        assembly ("memory-safe") {
            cached := mload(add(cache, shl(5, cacheSlot)))
        }
        uint256 lo;
        unchecked {
            if (cached >> 6 == uint256(idx) + 1) {
                lo = cached & 0x3f;
            } else {
                lo = StepLog.resolvePageMiss(ctx, idx, cacheSlot);
            }
        }
        bytes memory pd = ctx.pageData;
        bytes32[] memory hashes = ctx.pageHashes;
        uint256 pageSize = EmulatorConstants.PAGE_SIZE;
        uint256 pageMask = EmulatorConstants.PAGE_OFFSET_MASK;
        uint256 ptr;
        // A cache hit/miss resolves an existing position in both decoded arrays;
        // positions fit six bits and the aligned 32-byte slot stays within its page.
        assembly ("memory-safe") {
            mstore(add(add(hashes, 32), shl(5, lo)), 0)
            ptr := add(add(pd, 32), add(mul(lo, pageSize), and(slotAddr, pageMask)))
        }
        uint256 slot = (uint256(StepLog.swapBytes64(vaddrPage)) << 192)
            | (uint256(StepLog.swapBytes64(vpOffset)) << 128)
            | (uint256(StepLog.swapBytes64(pmaIndex)) << 64);
        assembly ("memory-safe") {
            mstore(ptr, slot)
        }
    }

    function throwRuntimeError(StepLog.Context memory, string memory message) internal pure {
        revert RuntimeError(message);
    }

    // Pure math helpers - transpiler bridge to uarch-solidity-compat.hpp.
    // `unchecked` everywhere to preserve C++ wraparound semantics.

    function uint32Log2(uint32 v) internal pure returns (uint32) {
        if (v == 0) revert Uint32Log2OfZero();
        uint32 r = 0;
        if (v >= 1 << 16) {
            v >>= 16;
            r += 16;
        }
        if (v >= 1 << 8) {
            v >>= 8;
            r += 8;
        }
        if (v >= 1 << 4) {
            v >>= 4;
            r += 4;
        }
        if (v >= 1 << 2) {
            v >>= 2;
            r += 2;
        }
        if (v >= 1 << 1) r += 1;
        return r;
    }

    function uint64AddInt32(uint64 v, int32 w) internal pure returns (uint64) {
        unchecked {
            return v + uint64(int64(w));
        }
    }

    function uint64AddUint64(uint64 v, uint64 w) internal pure returns (uint64) {
        unchecked {
            return v + w;
        }
    }

    function uint64SubUint64(uint64 v, uint64 w) internal pure returns (uint64) {
        unchecked {
            return v - w;
        }
    }

    function uint64ShiftRight(uint64 v, uint32 count) internal pure returns (uint64) {
        return v >> (count & 0x3f);
    }

    function uint64ShiftLeft(uint64 v, uint32 count) internal pure returns (uint64) {
        unchecked {
            return v << (count & 0x3f);
        }
    }

    function int64ShiftRight(int64 v, uint32 count) internal pure returns (int64) {
        return v >> (count & 0x3f);
    }

    function int64AddInt64(int64 v, int64 w) internal pure returns (int64) {
        unchecked {
            return v + w;
        }
    }

    function uint32ShiftRight(uint32 v, uint32 count) internal pure returns (uint32) {
        return v >> (count & 0x1f);
    }

    function uint32ShiftLeft(uint32 v, uint32 count) internal pure returns (uint32) {
        unchecked {
            return v << (count & 0x1f);
        }
    }

    function int32ShiftRight(int32 v, uint32 count) internal pure returns (int32) {
        return v >> (count & 0x1f);
    }

    function int32AddInt32(int32 v, int32 w) internal pure returns (int32) {
        unchecked {
            return v + w;
        }
    }

    function int32SubInt32(int32 v, int32 w) internal pure returns (int32) {
        unchecked {
            return v - w;
        }
    }

    /// C++ static_cast<int32>(uint64): low 32 bits reinterpreted as signed.
    function uint64ToInt32(uint64 v) internal pure returns (int32) {
        return int32(uint32(v));
    }

    function int32ToUint64(int32 v) internal pure returns (uint64) {
        return uint64(int64(v));
    }

    function int16ToUint64(int16 v) internal pure returns (uint64) {
        return uint64(int64(v));
    }

    function int8ToUint64(int8 v) internal pure returns (uint64) {
        return uint64(int64(v));
    }
}
