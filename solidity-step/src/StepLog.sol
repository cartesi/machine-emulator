// SPDX-License-Identifier: Apache-2.0
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
    /// Merkle-integrity check on the pre-state: recomputed root from pages+nodes
    /// +siblings did not match the header's rootHashBefore.
    error InitialRootHashMismatch();
    /// decode found bytes left over after the step log body.
    error TrailingBytes(uint256 consumed, uint256 length);
    /// A node's hashAfter is folded into the post-state root verbatim, so every node
    /// must be produced by a semantic write; some node was never consumed by the replay.
    error UnconsumedNodes(uint256 consumed, uint256 total);

    /// Decoded step log. Fields are unverified wire claims until Verify.verifyXXX runs computeRootHash.
    struct Context {
        bytes32 rootHashBefore;
        uint64 requestedCycleCount;
        bytes32 rootHashAfter;
        uint8 hashFunction;
        uint64[] pageIndices; // strictly ascending
        bytes pageData; // pageCount * PAGE_SIZE bytes; page i at offset i * PAGE_SIZE
        bytes32[] pageHashes; // filled by computeRootHash
        NodeEntry[] nodes; // internal nodes covering regions > PAGE_SIZE; strictly ascending by addr, no overlaps with pages
        bytes32[] siblings; // hash values for subtrees not covered by pages or nodes; left-to-right order
        uint256 consumedNodes; // count of nodes a semantic write looked up during replay; see computeRootHash
        bool reverted; // set when uarch reset reverted the state on a rejected input; see Verify.verifyReset
        bytes32 revertedRootHash; // canonical post-state hash when reverted (the recorded revert root hash)
    }

    uint256 internal constant HASH_SIZE = 32;
    uint256 internal constant U64_SIZE = 8;

    uint256 internal constant HEADER_SIZE = 8 // signature
        + HASH_SIZE // rootHashBefore
        + U64_SIZE // requestedCycleCount
        + HASH_SIZE // rootHashAfter
        + U64_SIZE // hashFunction
        + U64_SIZE // pageCount
        + U64_SIZE // nodeCount
        + U64_SIZE; // siblingCount

    uint256 internal constant PAGE_ENTRY_SIZE = U64_SIZE // page index
        + EmulatorConstants.PAGE_SIZE // data
        + HASH_SIZE; // scratch_hash

    /// Whole-subtree update encoded as pre/post hashes.
    struct NodeEntry {
        uint64 addr; // subtree start address
        uint64 log2Size; // log2 of subtree size (> page-log2, <= root-log2)
        bytes32 hashBefore; // subtree root hash before the step
        bytes32 hashAfter; // subtree root hash after the step
    }

    uint256 internal constant NODE_ENTRY_SIZE = U64_SIZE // addr
        + U64_SIZE // log2_size
        + HASH_SIZE // hash_before
        + HASH_SIZE; // hash_after

    // Witness-size caps. These only bound the decode work and reject pathological logs
    // early: the actual verification scope (a single uarch step, reset or cmio) is
    // enforced by Verify.verifyXXX (requested cycle count, root chain). A single uarch
    // step touches <=3 pages and reset/cmio <=1 node (corpus max 3/1/69), but the caps
    // admit a whole-mcycle log (corpus max 31 pages; see test/GasReport.t.sol) so gas
    // measurement runs against unmodified decode. Sibling cap must stay >= 52 (tree
    // depth) * MAX_PAGE_COUNT so a maximally-spread log is not wrongly rejected.
    uint64 internal constant MAX_PAGE_COUNT = 64;
    uint64 internal constant MAX_NODE_COUNT = 4;
    uint64 internal constant MAX_SIBLING_COUNT = 3328;

    /// Decode a standalone step log that must occupy the entire buffer; reverts on
    /// trailing bytes. Use `decodeAt` for multi-log cursor composition.
    function decode(bytes calldata data) internal pure returns (Context memory ctx) {
        uint256 newOffset;
        (ctx, newOffset) = decodeAt(data, 0);
        if (newOffset != data.length) revert TrailingBytes(newOffset, data.length);
    }

    /// Decode + structurally validate the step log at `offset`, verify its pre-state
    /// Merkle root, and return the offset just past it (cursor primitive for multi-log
    /// composition). The returned `rootHashBefore` is trustworthy; the post-state and
    /// caller-belief checks still happen in Verify.verifyXXX.
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

        ctx.rootHashBefore = bytes32(data[cursor:cursor + HASH_SIZE]);
        cursor += HASH_SIZE;

        ctx.requestedCycleCount = readLE64(data, cursor);
        cursor += U64_SIZE;

        ctx.rootHashAfter = bytes32(data[cursor:cursor + HASH_SIZE]);
        cursor += HASH_SIZE;

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

        // Counts are capped (MAX_*_COUNT), so total cannot overflow; offset <= data.length
        // holds from the header bound above, so the subtraction is safe.
        uint256 total = HEADER_SIZE + uint256(pageCount) * PAGE_ENTRY_SIZE
            + uint256(nodeCount) * NODE_ENTRY_SIZE + uint256(siblingCount) * HASH_SIZE;
        if (data.length - offset < total) revert LogTruncated();

        ctx.pageIndices = new uint64[](pageCount);
        ctx.pageData = new bytes(uint256(pageCount) * EmulatorConstants.PAGE_SIZE);
        ctx.pageHashes = new bytes32[](pageCount);

        for (uint64 i = 0; i < pageCount; i++) {
            uint64 idx = readLE64(data, cursor);
            cursor += U64_SIZE;
            if (i > 0 && idx <= ctx.pageIndices[i - 1]) revert PagesNotInOrder();
            ctx.pageIndices[i] = idx;

            copyPageData(data, cursor, ctx.pageData, i);
            cursor += EmulatorConstants.PAGE_SIZE;

            if (bytes32(data[cursor:cursor + HASH_SIZE]) != bytes32(0)) revert NonZeroScratchHash();
            cursor += HASH_SIZE;
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

            n.hashBefore = bytes32(data[cursor:cursor + HASH_SIZE]);
            cursor += HASH_SIZE;
            n.hashAfter = bytes32(data[cursor:cursor + HASH_SIZE]);
            cursor += HASH_SIZE;
            ctx.nodes[i] = n;
        }

        validateEntriesOrderedAndDisjoint(ctx);

        ctx.siblings = new bytes32[](siblingCount);
        for (uint64 i = 0; i < siblingCount; i++) {
            ctx.siblings[i] = bytes32(data[cursor:cursor + HASH_SIZE]);
            cursor += HASH_SIZE;
        }

        // Pre-state integrity: the recomputed root must match the header's claim.
        if (computeRootHash(ctx, false) != ctx.rootHashBefore) revert InitialRootHashMismatch();

        newOffset = cursor;
    }

    /// Combined pages+nodes stream must be strictly ascending and disjoint.
    function validateEntriesOrderedAndDisjoint(Context memory ctx) private pure {
        uint256 pi = 0; // page index cursor
        uint256 ni = 0; // node index cursor
        uint256 prevEnd = 0;
        uint256 pageSize = EmulatorConstants.PAGE_SIZE;
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
                uint256 pageStart =
                    uint256(ctx.pageIndices[pi]) << EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
                takePage = pageStart < ctx.nodes[ni].addr;
            }
            if (takePage) {
                entryStart =
                    uint256(ctx.pageIndices[pi]) << EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
                entryEnd = entryStart + pageSize;
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

    /// Hashes each page lazily into ctx.pageHashes, then folds the tree.
    /// `useAfter` picks each node's hashAfter (true) or hashBefore (false).
    /// A zero pageHashes slot means "needs hashing": slots start zero, and every write zeroes the
    /// written page's slot (findPageForWrite). So the pre-state call hashes all pages and the
    /// post-state call rehashes only the pages the operation wrote; clean pages keep the hash the
    /// pre-state call already validated against rootHashBefore, byte-identical after the step.
    function computeRootHash(Context memory ctx, bool useAfter) internal pure returns (bytes32) {
        uint256 pageCnt = ctx.pageIndices.length;
        for (uint256 i = 0; i < pageCnt; i++) {
            if (ctx.pageHashes[i] == bytes32(0)) {
                ctx.pageHashes[i] = HashTree.merkleTreeHash(
                    ctx.pageData, i * EmulatorConstants.PAGE_SIZE, EmulatorConstants.PAGE_SIZE
                );
            }
        }
        TreeWalkCursors memory c;
        bytes32 root = computeSubtreeHash(
            ctx,
            c,
            0, // start page index
            uint8(
                EmulatorConstants.HASH_TREE_LOG2_ROOT_SIZE
                    - EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE
            ), // log2PageCount
            useAfter
        );
        if (c.nextPage != pageCnt) revert TooManyPages();
        if (c.nextNode != ctx.nodes.length) revert TooManyNodes();
        if (c.nextSibling != ctx.siblings.length) revert TooManySiblings();
        if (useAfter) {
            checkAllNodesConsumed(ctx);
        }
        return root;
    }

    struct TreeWalkCursors {
        uint256 nextPage;
        uint256 nextNode;
        uint256 nextSibling;
    }

    /// Recursively computes the Merkle hash of one subtree, descending until each
    /// covered region resolves to a logged page, node, or sibling. Returns that hash.
    /// @param c        page/node/sibling cursors, advanced in place as entries are consumed
    /// @param useAfter pick each matched node's hashAfter (post-state) over hashBefore (pre-state)
    function computeSubtreeHash(
        Context memory ctx,
        TreeWalkCursors memory c,
        uint64 pageIndex,
        uint8 log2PageCount,
        bool useAfter
    ) private pure returns (bytes32) {
        uint256 subtreeStartAddr = uint256(pageIndex) << EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint8 subtreeLog2Size = log2PageCount + EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint64 subtreeEndPageIndex = pageIndex + (uint64(1) << log2PageCount);

        bool pageIn =
            c.nextPage < ctx.pageIndices.length && ctx.pageIndices[c.nextPage] < subtreeEndPageIndex;
        bool nodeIn = c.nextNode < ctx.nodes.length
            && (ctx.nodes[c.nextNode].addr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE)
                < subtreeEndPageIndex;

        if (!pageIn && !nodeIn) {
            // no page or node in this subtree, so it must be a sibling. The caller must have
            if (c.nextSibling >= ctx.siblings.length) revert TooFewSiblings();
            return ctx.siblings[c.nextSibling++];
        }

        if (
            nodeIn && ctx.nodes[c.nextNode].addr == subtreeStartAddr
                && ctx.nodes[c.nextNode].log2Size == subtreeLog2Size
        ) {
            // The subtree is fully covered by a node; consume it and return its hash.
            NodeEntry memory n = ctx.nodes[c.nextNode++];
            return useAfter ? n.hashAfter : n.hashBefore;
        }

        if (log2PageCount > 0) {
            // The subtree is partially covered by pages/nodes, so recurse to the left and right halves.
            bytes32 left = computeSubtreeHash(ctx, c, pageIndex, log2PageCount - 1, useAfter);
            uint64 halfwayPageIndex = pageIndex + (uint64(1) << (log2PageCount - 1));
            bytes32 right =
                computeSubtreeHash(ctx, c, halfwayPageIndex, log2PageCount - 1, useAfter);
            // combine through the EVM scratch space (0x00-0x40) rather than
            // abi.encodePacked, which would allocate a fresh buffer per tree node
            // (~100 nodes per verify); same idiom as HashTree.merkleTreeHash
            bytes32 parent;
            assembly ("memory-safe") {
                mstore(0x00, left)
                mstore(0x20, right)
                parent := keccak256(0x00, 0x40)
            }
            return parent;
        }
        // Leaf: must be a page (nodes have log2Size > HASH_TREE_LOG2_PAGE_SIZE).
        return ctx.pageHashes[c.nextPage++];
    }

    /// Assert every witnessed node was consumed by a semantic write during replay.
    /// Post-state soundness: each node's hashAfter is taken from the wire and folded into
    /// rootHashAfter, so an unconsumed node would inject an arbitrary post-state subtree. Every node
    /// must have been looked up by a semantic write (reset/cmio); a uarch step writes only pages, so it
    /// must carry no nodes at all. computeRootHash(true) calls this; a reverted operation substitutes a
    /// recorded root instead of recomputing it, so it must call this explicitly to keep the guarantee.
    function checkAllNodesConsumed(Context memory ctx) internal pure {
        if (ctx.consumedNodes != ctx.nodes.length) {
            revert UnconsumedNodes(ctx.consumedNodes, ctx.nodes.length);
        }
    }

    /// Returns a raw memory pointer to byte `paddr` inside ctx.pageData. Callers consume the pointer
    /// immediately in an assembly block; safe because `bytes memory` never moves. Read paths use this;
    /// write paths use findPageForWrite so the page is rehashed on the post-state root.
    function findPage(Context memory ctx, uint64 paddr) internal pure returns (uint256 memPtr) {
        (memPtr,) = locatePage(ctx, paddr);
    }

    /// Like findPage, but invalidates the page's cached hash (zeroes its pageHashes slot) so
    /// computeRootHash rehashes it on the post-state pass. Every path that mutates pageData resolves
    /// through here.
    function findPageForWrite(Context memory ctx, uint64 paddr)
        internal
        pure
        returns (uint256 memPtr)
    {
        uint256 pageIdx;
        (memPtr, pageIdx) = locatePage(ctx, paddr);
        ctx.pageHashes[pageIdx] = bytes32(0);
    }

    function locatePage(Context memory ctx, uint64 paddr)
        private
        pure
        returns (uint256 memPtr, uint256 pageIdx)
    {
        uint64 idx = paddr >> EmulatorConstants.HASH_TREE_LOG2_PAGE_SIZE;
        uint256 lo = 0;
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
        pageIdx = lo;
        uint256 byteOff = lo * EmulatorConstants.PAGE_SIZE
            + (uint256(paddr) & uint256(EmulatorConstants.PAGE_OFFSET_MASK));
        bytes memory pd = ctx.pageData;
        assembly ("memory-safe") {
            memPtr := add(add(pd, 32), byteOff)
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

    function copyPageData(bytes calldata data, uint256 srcOff, bytes memory dst, uint64 pageIdx)
        private
        pure
    {
        uint256 dstOff = uint256(pageIdx) * EmulatorConstants.PAGE_SIZE;
        uint256 pageSize = EmulatorConstants.PAGE_SIZE;
        assembly ("memory-safe") {
            // skip 32-byte length prefix
            let dstPtr := add(add(dst, 32), dstOff)
            calldatacopy(dstPtr, add(data.offset, srcOff), pageSize)
        }
    }

    function swapBytes64(uint64 v) internal pure returns (uint64) {
        return ((v & 0x00000000000000ff) << 56) | ((v & 0x000000000000ff00) << 40)
            | ((v & 0x0000000000ff0000) << 24) | ((v & 0x00000000ff000000) << 8)
            | ((v & 0x000000ff00000000) >> 8) | ((v & 0x0000ff0000000000) >> 24)
            | ((v & 0x00ff000000000000) >> 40) | ((v & 0xff00000000000000) >> 56);
    }
}
