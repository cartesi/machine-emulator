// SPDX-License-Identifier: Apache-2.0
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
    error WriteMemoryHashMismatch(bytes32 expected, bytes32 fromLog);
    error ResetUarchWrongSize(uint64 nodeLog2Size);
    error ResetUarchWrongPostHash(bytes32 fromLog);
    error Uint32Log2OfZero();
    /// Wraps the message from a C++ THROW(...) call site (transpiled via throwRuntimeError).
    error RuntimeError(string message);

    // Wire format stores multi-byte integers little-endian; the EVM word format
    // is big-endian. readWord / writeWord internalise the swap.

    function readWord(StepLog.Context memory ctx, uint64 paddr) internal pure returns (uint64) {
        if (paddr & 0x7 != 0) revert UnalignedWordAccess(paddr);
        uint256 ptr = StepLog.findPage(ctx, paddr);
        bytes32 word32;
        assembly ("memory-safe") {
            word32 := mload(ptr)
        }
        return StepLog.swapBytes64(uint64(bytes8(word32)));
    }

    function writeWord(StepLog.Context memory ctx, uint64 paddr, uint64 val) internal pure {
        if (paddr & 0x7 != 0) revert UnalignedWordAccess(paddr);
        uint256 ptr = StepLog.findPageForWrite(ctx, paddr);
        assembly ("memory-safe") {
            // Wire format is little-endian: byte 0 = LSB of val.
            mstore8(ptr, and(val, 0xff))
            mstore8(add(ptr, 1), and(shr(8, val), 0xff))
            mstore8(add(ptr, 2), and(shr(16, val), 0xff))
            mstore8(add(ptr, 3), and(shr(24, val), 0xff))
            mstore8(add(ptr, 4), and(shr(32, val), 0xff))
            mstore8(add(ptr, 5), and(shr(40, val), 0xff))
            mstore8(add(ptr, 6), and(shr(48, val), 0xff))
            mstore8(add(ptr, 7), and(shr(56, val), 0xff))
        }
    }

    function readHalt(StepLog.Context memory ctx) internal pure returns (uint64) {
        return readWord(ctx, EmulatorConstants.UARCH_HALT_ADDR);
    }

    function writeHalt(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.UARCH_HALT_ADDR, val);
    }

    function readCycle(StepLog.Context memory ctx) internal pure returns (uint64) {
        return readWord(ctx, EmulatorConstants.UARCH_CYCLE_ADDR);
    }

    function writeCycle(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.UARCH_CYCLE_ADDR, val);
    }

    function readPc(StepLog.Context memory ctx) internal pure returns (uint64) {
        return readWord(ctx, EmulatorConstants.UARCH_PC_ADDR);
    }

    function writePc(StepLog.Context memory ctx, uint64 val) internal pure {
        writeWord(ctx, EmulatorConstants.UARCH_PC_ADDR, val);
    }

    function readX(StepLog.Context memory ctx, uint8 reg) internal pure returns (uint64) {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) revert UarchXRegisterOutOfRange(reg);
        return readWord(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8);
    }

    function writeX(StepLog.Context memory ctx, uint8 reg, uint64 val) internal pure {
        if (reg >= EmulatorConstants.UARCH_X_REG_COUNT) revert UarchXRegisterOutOfRange(reg);
        writeWord(ctx, EmulatorConstants.UARCH_X_BASE_ADDR + uint64(reg) * 8, val);
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
    // the context and substituted as the final root hash by Verify.verifyReset.
    function revertState(StepLog.Context memory ctx) internal pure {
        ctx.reverted = true;
        ctx.revertedRootHash = readRevertRootHash(ctx);
    }

    // True when the tohost word holds a manual yield with the given reason. Mirrors isYieldedManualWith.
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
        bytes32 paddedHash = HashTree.merkleTreeHashPadded(data, uint8(writeLengthLog2Size));
        StepLog.NodeEntry memory n = StepLog.findNode(ctx, paddr);
        if (uint32(n.log2Size) != writeLengthLog2Size) {
            revert WriteMemoryNodeWrongSize(writeLengthLog2Size, n.log2Size);
        }
        if (n.hashAfter != paddedHash) revert WriteMemoryHashMismatch(paddedHash, n.hashAfter);
        ctx.consumedNodes++;
    }

    /// Mirrors do_reset_uarch in uarch-replay-step-state-access.hpp.
    function resetState(StepLog.Context memory ctx) internal pure {
        StepLog.NodeEntry memory n = StepLog.findNode(ctx, EmulatorConstants.UARCH_STATE_START_ADDR);
        if (n.log2Size != EmulatorConstants.UARCH_STATE_LOG2_SIZE) {
            revert ResetUarchWrongSize(n.log2Size);
        }
        if (n.hashAfter != EmulatorConstants.UARCH_PRISTINE_STATE_HASH) {
            revert ResetUarchWrongPostHash(n.hashAfter);
        }
        ctx.consumedNodes++;
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
        uint64 slotAddr = EmulatorConstants.AR_SHADOW_TLB_START
            + setIndex * EmulatorConstants.SHADOW_TLB_SET_LENGTH
            + slotIndex * EmulatorConstants.SHADOW_TLB_SLOT_SIZE;

        writeWord(ctx, slotAddr + 0, vaddrPage);
        writeWord(ctx, slotAddr + 8, vpOffset);
        writeWord(ctx, slotAddr + 16, pmaIndex);
        writeWord(ctx, slotAddr + 24, 0); // zero_padding_
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
