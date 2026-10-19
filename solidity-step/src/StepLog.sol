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

/// Binary step log decoder.
library StepLog {
    error HeaderTruncated();
    error InvalidSignature();
    error UnsupportedHashFunction(uint64 code);
    error LogTruncated();
    /// A valid step log always witnesses at least one page; a zero page count is malformed.
    error PageCountZero();
    error PagesNotInOrder();
    error SliceLog2SizeOutOfRange(uint64 log2Size);
    error SliceNotAligned(uint64 addr, uint64 log2Size);
    error SlicesOverlap();
    error MultipleSlicesInPage();
    error AccessOutsideSlice();
    error InvalidSliceSubtree();
    /// A page entry's scratch_hash field is reserved and must be zero on the wire.
    error NonZeroScratchHash();
    error NodeLog2SizeOutOfRange(uint64 log2Size);
    error NodeNotAligned(uint64 addr, uint64 log2Size);
    error OverlappingEntries();
    error TooManyPages();
    error TooManyNodes();
    error TooManySiblings();
    error TooFewSiblings();
    error PageCountExceedsLimit(uint64 declared);
    error NodeCountExceedsLimit(uint64 declared);
    error SiblingCountExceedsLimit(uint64 declared);
    error RequiredPageNotFound(uint64 pageIdx);
    error RequiredNodeNotFound(uint64 addr);
    /// decode found bytes left over after the step log body.
    error TrailingBytes(uint256 consumed, uint256 length);

    /// Decoded step log. rootHashBefore is recomputed from the witnessed tree at decode time.
    struct Context {
        bytes32 rootHashBefore;
        uint8 hashFunction;
        uint64[] pageIndices; // strictly ascending
        uint256[] slices; // same order as pageIndices; one aligned region per page
        bytes pageData; // concatenated slice contents; writes materialize before hashing/raw access
        bytes32[] pageHashes; // filled by computeRootHash
        NodeEntry[] nodes; // internal nodes covering regions > PAGE_SIZE; strictly ascending by addr, no overlaps with pages
        bytes32[] siblings; // hash values for subtrees not covered by pages or nodes; left-to-right order
        bool reverted; // set when uarch reset reverted the state on a rejected input; see Verify.verifyReset
        bytes32 revertedRootHash; // canonical post-state hash when reverted (the recorded revert root hash)
        uint256[61] pageLookupCache; // (page index + 1) above 6 position bits; zero means uncached
        uint64[35] uarchRegisters; // halt, cycle, PC, and 32 integer registers
        uint256 uarchShadowPtr; // zero when the register cache needs loading
        uint256 uarchShadowPageIndex;
        bool uarchRegistersDirty;
    }

    uint256 internal constant UARCH_REGISTER_WORD_COUNT =
        EmulatorConstants.UARCH_REGISTER_WORD_COUNT;

    uint256 internal constant HASH_SIZE = 32;
    uint256 internal constant U64_SIZE = 8;

    uint256 internal constant HEADER_SIZE = 8 // signature
        + U64_SIZE // hashFunction
        + U64_SIZE // pageCount
        + U64_SIZE // nodeCount
        + U64_SIZE; // siblingCount

    uint256 internal constant SLICE_HEADER_SIZE = 2 * U64_SIZE;
    uint256 internal constant MIN_SLICE_ENTRY_SIZE = SLICE_HEADER_SIZE + 32 + HASH_SIZE;

    // Slices are 32-byte aligned: pack log2 size in the address's spare low
    // five bits, and content offset above bit 63. Decode validates size/alignment
    // and bounds the offset by 64 * 4096 bytes. The wire is unchanged.
    function packSlice(uint64 addr, uint64 log2Size, uint256 dataOffset)
        internal
        pure
        returns (uint256)
    {
        return uint256(addr) | uint256(log2Size) | (dataOffset << 64);
    }

    function sliceAddress(uint256 slice) internal pure returns (uint64) {
        return uint64(slice) & ~uint64(31);
    }

    function sliceLog2Size(uint256 slice) internal pure returns (uint8) {
        return uint8(slice & 31);
    }

    function sliceDataOffset(uint256 slice) internal pure returns (uint256) {
        return slice >> 64;
    }

    /// A subtree whose contents are not witnessed, only its hash. The wire value is the
    /// subtree hash before the step; a replayed bulk write overwrites the slot with the
    /// hash computed from the write's own arguments, so the slot always holds the current hash.
    struct NodeEntry {
        uint64 addr; // subtree start address
        uint64 log2Size; // log2 of subtree size (> page-log2, <= root-log2)
        bytes32 hash; // subtree hash, kept current during replay
    }

    uint256 internal constant NODE_ENTRY_SIZE = U64_SIZE // addr
        + U64_SIZE // log2_size
        + HASH_SIZE; // hash

    // Decode caps bound work and memory. Slice siblings can occur down to the
    // 32-byte leaf: 59 levels per slice, plus at most 51 per bulk-write node.
    uint64 internal constant MAX_PAGE_COUNT = 64;
    uint64 internal constant MAX_NODE_COUNT = 4;
    uint64 internal constant MAX_SIBLING_COUNT = 59 * MAX_PAGE_COUNT + 51 * MAX_NODE_COUNT;

    /// Decode a standalone step log that must occupy the entire buffer; reverts on
    /// trailing bytes. Use `decodeAt` for multi-log cursor composition.
    function decode(bytes calldata data) internal pure returns (Context memory ctx) {
        uint256 newOffset;
        (ctx, newOffset) = decodeAt(data, 0);
        if (newOffset != data.length) revert TrailingBytes(newOffset, data.length);
    }

    /// Decode + structurally validate the step log at `offset`, recompute its pre-state
    /// Merkle root into `rootHashBefore`, and return the offset just past it (cursor
    /// primitive for multi-log composition). The caller-belief checks happen in
    /// Verify.verifyXXX.
    function decodeAt(bytes calldata data, uint256 offset)
        internal
        pure
        returns (Context memory ctx, uint256 newOffset)
    {
        // Subtraction-style bounds: offset is caller-supplied, so offset + HEADER_SIZE
        // could overflow and panic before this revert. Compare against the remaining
        // length instead.
        if (offset > data.length || data.length - offset < HEADER_SIZE) revert HeaderTruncated();
        uint256 cursor = offset;

        if (bytes8(data[cursor:cursor + 8]) != EmulatorConstants.STEP_LOG_SIGNATURE) {
            revert InvalidSignature();
        }
        cursor += 8;

        // This verifier implements keccak256 only
        uint64 hashFn = readLE64(data, cursor);
        cursor += U64_SIZE;
        if (hashFn != EmulatorConstants.HASH_FUNCTION_KECCAK256) {
            revert UnsupportedHashFunction(hashFn);
        }
        ctx.hashFunction = uint8(hashFn);

        uint64 pageCount = readLE64(data, cursor);
        cursor += U64_SIZE;
        uint64 nodeCount = readLE64(data, cursor);
        cursor += U64_SIZE;
        uint64 siblingCount = readLE64(data, cursor);
        cursor += U64_SIZE;

        if (pageCount > MAX_PAGE_COUNT) revert PageCountExceedsLimit(pageCount);
        if (pageCount == 0) revert PageCountZero();
        if (nodeCount > MAX_NODE_COUNT) revert NodeCountExceedsLimit(nodeCount);
        if (siblingCount > MAX_SIBLING_COUNT) revert SiblingCountExceedsLimit(siblingCount);

        uint256 minimum = uint256(pageCount) * MIN_SLICE_ENTRY_SIZE
            + uint256(nodeCount) * NODE_ENTRY_SIZE + uint256(siblingCount) * HASH_SIZE;
        if (data.length - cursor < minimum) revert LogTruncated();

        cursor = decodeSlices(data, cursor, pageCount, ctx);
        if (
            data.length - cursor
                < uint256(nodeCount) * NODE_ENTRY_SIZE + uint256(siblingCount) * HASH_SIZE
        ) {
            revert LogTruncated();
        }

        ctx.nodes = new NodeEntry[](nodeCount);
        for (uint64 i = 0; i < nodeCount; i++) {
            NodeEntry memory n;

            n.addr = readLE64(data, cursor);
            cursor += U64_SIZE;

            uint64 log2Size = readLE64(data, cursor);
            cursor += U64_SIZE;
            if (
                log2Size <= EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE
                    || log2Size > EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE
            ) revert NodeLog2SizeOutOfRange(log2Size);
            n.log2Size = log2Size;
            // alignment: addr % (1<<log2Size) == 0. The root size covers the entire u64 space, so addr must be 0.
            if (log2Size == EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE) {
                if (n.addr != 0) revert NodeNotAligned(n.addr, n.log2Size);
            } else {
                if ((n.addr & ((uint256(1) << log2Size) - 1)) != 0) {
                    revert NodeNotAligned(n.addr, n.log2Size);
                }
            }

            n.hash = bytes32(data[cursor:cursor + HASH_SIZE]);
            cursor += HASH_SIZE;
            ctx.nodes[i] = n;
        }

        validateEntriesOrderedAndDisjoint(ctx);

        ctx.siblings = new bytes32[](siblingCount);
        for (uint64 i = 0; i < siblingCount; i++) {
            ctx.siblings[i] = bytes32(data[cursor:cursor + HASH_SIZE]);
            cursor += HASH_SIZE;
        }

        ctx.rootHashBefore = computeRootHash(ctx);

        newOffset = cursor;
    }

    function decodeSlices(bytes calldata data, uint256 cursor, uint64 pageCount, Context memory ctx)
        private
        pure
        returns (uint256)
    {
        ctx.pageIndices = new uint64[](pageCount);
        ctx.slices = new uint256[](pageCount);
        ctx.pageHashes = new bytes32[](pageCount);
        uint256 sliceStart = cursor;
        uint256 contentBytes;
        for (uint256 i; i < pageCount; ++i) {
            if (data.length - cursor < SLICE_HEADER_SIZE) revert LogTruncated();
            uint64 addr = readLE64(data, cursor);
            uint64 log2Size = readLE64(data, cursor + U64_SIZE);
            cursor += SLICE_HEADER_SIZE;
            if (log2Size < 5 || log2Size > 12) revert SliceLog2SizeOutOfRange(log2Size);
            uint256 size = uint256(1) << log2Size;
            if (uint256(addr) & (size - 1) != 0) revert SliceNotAligned(addr, log2Size);
            if (data.length - cursor < size + HASH_SIZE) revert LogTruncated();
            uint64 idx = addr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
            if (i != 0) {
                uint256 prev = ctx.slices[i - 1];
                if (addr <= sliceAddress(prev)) revert PagesNotInOrder();
                if (
                    uint256(addr)
                        < uint256(sliceAddress(prev)) + (uint256(1) << sliceLog2Size(prev))
                ) {
                    revert SlicesOverlap();
                }
                if (idx == ctx.pageIndices[i - 1]) revert MultipleSlicesInPage();
            }
            ctx.pageIndices[i] = idx;
            ctx.slices[i] = packSlice(addr, log2Size, contentBytes);
            contentBytes += size;
            cursor += size;
            if (bytes32(data[cursor:cursor + HASH_SIZE]) != bytes32(0)) {
                revert NonZeroScratchHash();
            }
            cursor += HASH_SIZE;
        }
        // Size the allocation to the witnessed contents, not the enclosing pages.
        ctx.pageData = new bytes(contentBytes);
        uint256 copyCursor = sliceStart;
        for (uint256 i; i < pageCount; ++i) {
            uint256 slice = ctx.slices[i];
            uint256 size = uint256(1) << sliceLog2Size(slice);
            copySliceData(
                data, copyCursor + SLICE_HEADER_SIZE, ctx.pageData, sliceDataOffset(slice), size
            );
            copyCursor += SLICE_HEADER_SIZE + size + HASH_SIZE;
        }
        return cursor;
    }

    /// Combined pages+nodes stream must be strictly ascending and disjoint.
    function validateEntriesOrderedAndDisjoint(Context memory ctx) private pure {
        uint256 pi = 0; // page index cursor
        uint256 ni = 0; // node index cursor
        uint256 prevEnd = 0;
        uint256 pageCnt = ctx.pageIndices.length;
        uint256 nodeCnt = ctx.nodes.length;
        while (pi < pageCnt || ni < nodeCnt) {
            uint256 entryStart;
            uint256 entryEnd;
            bool takePage;
            if (pi >= pageCnt) {
                takePage = false;
            } else if (ni >= nodeCnt) {
                takePage = true;
            } else {
                takePage = sliceAddress(ctx.slices[pi]) < ctx.nodes[ni].addr;
            }
            if (takePage) {
                entryStart = sliceAddress(ctx.slices[pi]);
                entryEnd = entryStart + (uint256(1) << sliceLog2Size(ctx.slices[pi]));
                pi++;
            } else {
                entryStart = ctx.nodes[ni].addr;
                entryEnd = entryStart + (uint256(1) << ctx.nodes[ni].log2Size);
                ni++;
            }
            if (entryStart < prevEnd) revert OverlappingEntries();
            prevEnd = entryEnd;
        }
    }

    /// Hashes each page lazily into ctx.pageHashes, then folds the tree over its current state.
    /// A zero pageHashes slot means "needs hashing": writes invalidate the written page's slot
    /// (findPageForWrite or the first pending writeUarchWord). So decode hashes all pages and the
    /// post-state call rehashes only the pages the operation wrote. Node slots are used as they
    /// stand; replayed bulk writes keep them current.
    function computeRootHash(Context memory ctx) internal pure returns (bytes32) {
        flushUarchRegisters(ctx);
        uint256 pageCnt = ctx.pageIndices.length;
        for (uint256 i = 0; i < pageCnt; i++) {
            if (ctx.pageHashes[i] == bytes32(0)) {
                ctx.pageHashes[i] = HashTree.merkleTreeHashAsm(
                    ctx.pageData,
                    sliceDataOffset(ctx.slices[i]),
                    uint256(1) << sliceLog2Size(ctx.slices[i])
                );
            }
        }
        TreeWalkCursors memory c;
        bytes32 root = computeSubtreeHashAsm(ctx, c, 0, EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE);
        if (c.nextPage != pageCnt) revert TooManyPages();
        if (c.nextNode != ctx.nodes.length) revert TooManyNodes();
        if (c.nextSibling != ctx.siblings.length) revert TooManySiblings();
        return root;
    }

    struct TreeWalkCursors {
        uint256 nextPage;
        uint256 nextNode;
        uint256 nextSibling;
    }

    /// Recursively computes the Merkle hash of one subtree, descending until each
    /// covered region resolves to a logged page, node, or sibling. Returns that hash.
    /// @param c page/node/sibling cursors, advanced in place as entries are consumed
    function computeSubtreeHash(
        Context memory ctx,
        TreeWalkCursors memory c,
        uint64 addr,
        uint8 log2Size
    ) internal pure returns (bytes32) {
        uint256 end = uint256(addr) + (uint256(1) << log2Size);
        bool pageIn = c.nextPage < ctx.slices.length && sliceAddress(ctx.slices[c.nextPage]) < end;
        bool nodeIn = c.nextNode < ctx.nodes.length && ctx.nodes[c.nextNode].addr < end;
        if (!pageIn && !nodeIn) {
            if (c.nextSibling >= ctx.siblings.length) revert TooFewSiblings();
            return ctx.siblings[c.nextSibling++];
        }
        if (
            nodeIn && ctx.nodes[c.nextNode].addr == addr
                && ctx.nodes[c.nextNode].log2Size == log2Size
        ) {
            return ctx.nodes[c.nextNode++].hash;
        }
        if (
            pageIn && sliceAddress(ctx.slices[c.nextPage]) == addr
                && sliceLog2Size(ctx.slices[c.nextPage]) == log2Size
        ) {
            return ctx.pageHashes[c.nextPage++];
        }
        if (log2Size <= EmulatorConstants.HASH_TREE_LOG2_WORD_SIZE) revert InvalidSliceSubtree();
        bytes32 left = computeSubtreeHash(ctx, c, addr, log2Size - 1);
        bytes32 right =
            computeSubtreeHash(ctx, c, addr + (uint64(1) << (log2Size - 1)), log2Size - 1);
        bytes32 parent;
        assembly ("memory-safe") {
            mstore(0x00, left)
            mstore(0x20, right)
            parent := keccak256(0x00, 0x40)
        }
        return parent;
    }

    /// Assembly twin of computeSubtreeHash, over the same validated, disjoint entries.
    /// The root walk spans byte addresses [0, 2^64), descending to slice size.
    /// Array reads are guarded by their cursors. Exact slice matches select hashes from the equally sized pageHashes table.
    function computeSubtreeHashAsm(
        Context memory ctx,
        TreeWalkCursors memory c,
        uint64 addr,
        uint8 log2Size
    ) internal pure returns (bytes32 result) {
        // Pin the page shift and maximum depth used below; both assertions fold away.
        assert(EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE == 12);
        assert(EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE == 64);
        uint256[] memory slices = ctx.slices;
        NodeEntry[] memory nodes = ctx.nodes;
        bytes32[] memory siblings = ctx.siblings;
        bytes32[] memory pageHashes = ctx.pageHashes;
        // Allocated walk state: three cursors, then slices, nodes, siblings,
        // and pageHashes pointers, at offsets 0x00 through 0xc0. No Context offsets.
        uint256[7] memory w;
        assembly ("memory-safe") {
            function walk(w_, address_, log2Size_) -> h {
                let endAddress := add(address_, shl(log2Size_, 1))
                let pageIn := 0
                let slice := 0
                {
                    let pages := mload(add(w_, 0x60))
                    let np := mload(w_)
                    if lt(np, mload(pages)) {
                        slice := mload(add(pages, add(0x20, shl(5, np))))
                        pageIn := lt(and(slice, 0xffffffffffffffe0), endAddress)
                    }
                }
                let nodeIn := 0
                let nptr := 0
                {
                    let nodes_ := mload(add(w_, 0x80))
                    let nn := mload(add(w_, 0x20))
                    if lt(nn, mload(nodes_)) {
                        // A memory array of structs contains pointers to the structs.
                        nptr := mload(add(nodes_, add(0x20, shl(5, nn))))
                        nodeIn := lt(mload(nptr), endAddress)
                    }
                }
                if iszero(or(pageIn, nodeIn)) {
                    let sibs := mload(add(w_, 0xa0))
                    let ns := mload(add(w_, 0x40))
                    if iszero(lt(ns, mload(sibs))) {
                        mstore(0x00, shl(224, 0x245a1128)) // TooFewSiblings()
                        revert(0x00, 0x04)
                    }
                    h := mload(add(sibs, add(0x20, shl(5, ns))))
                    mstore(add(w_, 0x40), add(ns, 1))
                    leave
                }
                if nodeIn {
                    // Current NodeEntry: addr, log2Size, one current hash.
                    if and(eq(mload(nptr), address_), eq(mload(add(nptr, 0x20)), log2Size_)) {
                        mstore(add(w_, 0x20), add(mload(add(w_, 0x20)), 1))
                        h := mload(add(nptr, 0x40))
                        leave
                    }
                }
                if pageIn {
                    if and(
                        eq(and(slice, 0xffffffffffffffe0), address_), eq(and(slice, 31), log2Size_)
                    ) {
                        let np := mload(w_)
                        h := mload(add(mload(add(w_, 0xc0)), add(0x20, shl(5, np))))
                        mstore(w_, add(np, 1))
                        leave
                    }
                }
                if iszero(gt(log2Size_, 5)) {
                    mstore(0x00, shl(224, 0xabe197a9)) // InvalidSliceSubtree()
                    revert(0x00, 0x04)
                }
                let halfLog2 := sub(log2Size_, 1)
                let left := walk(w_, address_, halfLog2)
                let right := walk(w_, add(address_, shl(halfLog2, 1)), halfLog2)
                mstore(0x00, left)
                mstore(0x20, right)
                h := keccak256(0x00, 0x40)
            }
            mstore(w, mload(c))
            mstore(add(w, 0x20), mload(add(c, 0x20)))
            mstore(add(w, 0x40), mload(add(c, 0x40)))
            mstore(add(w, 0x60), slices)
            mstore(add(w, 0x80), nodes)
            mstore(add(w, 0xa0), siblings)
            mstore(add(w, 0xc0), pageHashes)
            result := walk(w, and(addr, 0xffffffffffffffff), and(log2Size, 0xff))
            mstore(c, mload(w))
            mstore(add(c, 0x20), mload(add(w, 0x20)))
            mstore(add(c, 0x40), mload(add(w, 0x40)))
        }
    }

    function findPage(Context memory ctx, uint64 paddr) internal pure returns (uint256) {
        return findPage(ctx, paddr, 8);
    }

    function findPageForWrite(Context memory ctx, uint64 paddr) internal pure returns (uint256) {
        return findPageForWrite(ctx, paddr, 8);
    }

    /// Returns a raw memory pointer to byte `paddr` inside ctx.pageData. Callers consume the pointer
    /// immediately in an assembly block; safe because `bytes memory` never moves. Read paths use this;
    /// write paths use findPageForWrite so the page is rehashed on the post-state root.
    function findPage(Context memory ctx, uint64 paddr, uint256 length)
        internal
        pure
        returns (uint256 memPtr)
    {
        if (isUarchShadowPage(paddr)) flushUarchRegisters(ctx);
        (memPtr,) = locatePage(ctx, paddr, length);
    }

    /// Like findPage, but invalidates the page's cached hash (zeroes its pageHashes slot) so
    /// computeRootHash rehashes it on the post-state pass. A raw write also invalidates cached
    /// registers on this page, so subsequent register reads observe the written bytes.
    function findPageForWrite(Context memory ctx, uint64 paddr, uint256 length)
        internal
        pure
        returns (uint256 memPtr)
    {
        if (isUarchShadowPage(paddr)) {
            flushUarchRegisters(ctx);
            ctx.uarchShadowPtr = 0;
        }
        uint256 pageIdx;
        (memPtr, pageIdx) = locatePage(ctx, paddr, length);
        ctx.pageHashes[pageIdx] = bytes32(0);
    }

    function isUarchShadowPage(uint64 paddr) private pure returns (bool) {
        return (paddr & ~EmulatorConstants.PAGE_OFFSET_MASK)
            == EmulatorConstants.AR_SHADOW_UARCH_STATE_START;
    }

    function readUarchWord(Context memory ctx, uint256 wordIndex) internal pure returns (uint64) {
        if (ctx.uarchShadowPtr == 0) loadUarchRegisters(ctx);
        return ctx.uarchRegisters[wordIndex];
    }

    function writeUarchWord(Context memory ctx, uint256 wordIndex, uint64 value) internal pure {
        if (ctx.uarchShadowPtr == 0) loadUarchRegisters(ctx);
        ctx.uarchRegisters[wordIndex] = value;
        // The hash stays invalid while writes are pending; hashing first flushes the registers.
        if (!ctx.uarchRegistersDirty) {
            ctx.uarchRegistersDirty = true;
            ctx.pageHashes[ctx.uarchShadowPageIndex] = bytes32(0);
        }
    }

    // Call only when the cache is empty. Keep the check at the callers so warm
    // register accesses avoid entering this cold loader.
    // Internal for StateAccess's inline accessors; no external ABI is added.
    function loadUarchRegisters(Context memory ctx) internal pure {
        (ctx.uarchShadowPtr, ctx.uarchShadowPageIndex) =
            locatePage(ctx, EmulatorConstants.UARCH_HALT_ADDR, UARCH_REGISTER_WORD_COUNT * 8);
        // Exactly 35 words (280 bytes), touching the same nine 32-byte leaves
        // marked by step_log_recorder::touch_page. Check once before bulk load/flush.
        assert(
            UARCH_REGISTER_WORD_COUNT * 8
                == EmulatorConstants.UARCH_REGISTER_END_ADDR - EmulatorConstants.UARCH_HALT_ADDR
        );
        // Check the fixed length against the generated register layout.
        assert(ctx.uarchRegisters.length == UARCH_REGISTER_WORD_COUNT);
        for (uint256 i; i < UARCH_REGISTER_WORD_COUNT; ++i) {
            uint256 ptr = ctx.uarchShadowPtr + i * 8;
            uint64 value;
            assembly ("memory-safe") {
                value := shr(192, mload(ptr))
            }
            ctx.uarchRegisters[i] = swapBytes64(value);
        }
    }

    /// Materialize pending register writes before hashing or exposing the page bytes.
    function flushUarchRegisters(Context memory ctx) internal pure {
        if (!ctx.uarchRegistersDirty) return;
        for (uint256 i; i < UARCH_REGISTER_WORD_COUNT; ++i) {
            writeLE64Memory(ctx.uarchShadowPtr + i * 8, ctx.uarchRegisters[i]);
        }
        ctx.uarchRegistersDirty = false;
    }

    function writeLE64Memory(uint256 ptr, uint64 val) internal pure {
        // Callers provide eight witnessed bytes and invalidate their page hash before writing.
        assembly ("memory-safe") {
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

    function locatePage(Context memory ctx, uint64 paddr, uint256 length)
        private
        pure
        returns (uint256 memPtr, uint256 pageIdx)
    {
        // decode caps the table at 64 pages; cache positions fit in six bits.
        // Search indices stay in 0..64 and byteOff is below 64 * PAGE_SIZE.
        // Array bounds checks and missing-page rejection are unchanged.
        unchecked {
            uint64 idx = paddr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
            uint256 cacheSlot = uint256(idx) % ctx.pageLookupCache.length;
            uint256 cached = ctx.pageLookupCache[cacheSlot];
            uint256 lo;
            // Physical page indices use 52 bits; adding one safely reserves tag zero.
            uint256 tag = uint256(idx) + 1;
            if (cached >> 6 == tag) {
                lo = cached & 0x3f;
            } else {
                lo = resolvePageMiss(ctx, idx, cacheSlot);
            }
            pageIdx = lo;
            memPtr = slicePointer(ctx, lo, paddr, length);
        }
    }

    /// Resolve checked bytes within a known slice; subtraction rejects addresses below its start.
    function slicePointer(Context memory ctx, uint256 pos, uint64 paddr, uint256 length)
        internal
        pure
        returns (uint256 ptr)
    {
        uint256 slice = ctx.slices[pos];
        uint256 size = uint256(1) << sliceLog2Size(slice);
        uint256 offset;
        unchecked {
            offset = uint256(paddr) - sliceAddress(slice);
        }
        if (length > size || offset > size - length) revert AccessOutsideSlice();
        uint256 byteOff = sliceDataOffset(slice) + offset;
        bytes memory pd = ctx.pageData;
        assembly ("memory-safe") {
            ptr := add(add(pd, 32), byteOff)
        }
    }

    // Shared cold path for locatePage and StateAccess's inline read/write cache hits.
    // Callers pass idx % pageLookupCache.length as cacheSlot.
    // Internal for the StateAccess caller; this adds no external ABI.
    function resolvePageMiss(Context memory ctx, uint64 idx, uint256 cacheSlot)
        internal
        pure
        returns (uint256 lo)
    {
        // decode caps the table at 64 pages; search endpoints stay in 0..64.
        unchecked {
            uint256 hi = ctx.pageIndices.length;
            while (lo < hi) {
                uint256 mid = (lo + hi) >> 1;
                if (ctx.pageIndices[mid] < idx) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if (lo >= ctx.pageIndices.length || ctx.pageIndices[lo] != idx) {
                revert RequiredPageNotFound(idx);
            }
            // A nonzero tag distinguishes page zero from an empty cache slot.
            ctx.pageLookupCache[cacheSlot] = ((uint256(idx) + 1) << 6) | lo;
        }
    }

    // Find a node by its subtree start address.
    function findNode(Context memory ctx, uint64 addr) internal pure returns (NodeEntry memory) {
        for (uint256 i = 0; i < ctx.nodes.length; i++) {
            if (ctx.nodes[i].addr == addr) return ctx.nodes[i];
        }
        revert RequiredNodeNotFound(addr);
    }

    function readLE64(bytes calldata data, uint256 off) private pure returns (uint64) {
        return swapBytes64(uint64(bytes8(data[off:off + 8])));
    }

    function copySliceData(
        bytes calldata data,
        uint256 srcOff,
        bytes memory dst,
        uint256 dstOff,
        uint256 size
    ) private pure {
        assembly ("memory-safe") {
            calldatacopy(add(add(dst, 32), dstOff), add(data.offset, srcOff), size)
        }
    }

    function swapBytes64(uint64 v) internal pure returns (uint64) {
        // Reverse adjacent bytes, then 16-bit pairs, then the 32-bit halves.
        v = ((v & 0x00ff00ff00ff00ff) << 8) | ((v >> 8) & 0x00ff00ff00ff00ff);
        v = ((v & 0x0000ffff0000ffff) << 16) | ((v >> 16) & 0x0000ffff0000ffff);
        return (v << 32) | (v >> 32);
    }
}
