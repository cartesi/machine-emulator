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

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

/// Shared base for tests that walk a `_manifest.csv` produced by
/// tests/lua/uarch-riscv-tests.lua. Unknown kinds map to `Kind.Unknown` so
/// readers stay forward-compatible with fixture kinds added later.
abstract contract ManifestParser is Test {
    enum Kind {
        Unknown,
        Cycle,
        ResetUarch,
        SendCmioResponse
    }

    // A row is a call recipe plus an expected outcome: the arguments to pass to the
    // verifier and either success (blank expectError) or the named rejection it must
    // revert with. Valid rows carry recorded truth; reject rows carry deliberately
    // wrong call arguments.
    // The cmio `data` column is the payload's repeat unit: the payload is the unit
    // cycled and trimmed to dataLength. Full payloads are the identity case (unit
    // length == dataLength); oversized fixtures store a tiny unit instead of
    // megabytes of CSV. Plain ASCII, recorder-controlled, CSV-safe.
    struct Row {
        Kind kind;
        string name;
        uint64 requestedCycleCount;
        bytes32 rootHashBefore;
        bytes32 rootHashAfter;
        uint16 reason;
        uint32 dataLength;
        bytes data;
        // Value written to the revert-root-hash shadow slot (cmio + reset rows); zero otherwise.
        bytes32 revertRootHash;
        // Names the rejection a corrupt fixture must trigger (reject fixtures); blank means
        // the log must replay successfully.
        string expectError;
    }

    // Per-cycle uarch fixtures: one subdirectory per rv64ui-uarch program, each with that program's
    // single-cycle logs and a _manifest.csv. The directory layout is the index (see programDirs).
    string constant UARCH_PER_CYCLE_DIR = "test/fixtures/uarch-tests-per-cycle";

    // Duplicated verbatim from the recorder's HEADER (tests/lua/cartesi/tests/step_log_manifest.lua)
    // on purpose: it pins the schema this parser was written against, so a fixture set recorded by a
    // different schema fails as "manifest schema mismatch" instead of a parse error deep in some row.
    string constant EXPECTED_HEADER = "kind,name,expectError,hashFunction,requestedCycleCount,"
        "rootHashBefore,rootHashAfter,reason,dataLength,data,revertRootHash";

    /// The per-cycle program subdirectories, read straight from the filesystem so the fixture set is
    /// self-contained -- no separate roster file to generate or keep in sync. Each entry is a path
    /// like `test/fixtures/uarch-tests-per-cycle/rv64ui-uarch-add`; append `/_manifest.csv` for its
    /// cycle rows.
    function programDirs() internal view returns (string[] memory dirs) {
        VmSafe.DirEntry[] memory entries = vm.readDir(UARCH_PER_CYCLE_DIR);
        uint256 n = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].isDir) n++;
        }
        dirs = new string[](n);
        uint256 j = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].isDir) dirs[j++] = entries[i].path;
        }
    }

    /// Returns the rows of `path` matching `kind`; others are skipped.
    /// Two-pass: count, then allocate exactly and fill.
    function readManifestRows(string memory path, Kind kind) internal returns (Row[] memory) {
        string memory header = vm.readLine(path);
        require(
            keccak256(bytes(header)) == keccak256(bytes(EXPECTED_HEADER)),
            "manifest schema mismatch"
        );
        uint256 n = 0;
        while (true) {
            string memory line = vm.readLine(path);
            if (bytes(line).length == 0) break;
            if (parseRow(line).kind == kind) n++;
        }
        vm.closeFile(path);

        Row[] memory out = new Row[](n);
        vm.readLine(path); // header
        uint256 i = 0;
        while (i < n) {
            string memory line = vm.readLine(path);
            if (bytes(line).length == 0) break;
            Row memory r = parseRow(line);
            if (r.kind == kind) out[i++] = r;
        }
        vm.closeFile(path);
        return out;
    }

    /// First row of `path` matching `kind`; reverts if there are none.
    /// Returns the row of `kind` whose `name` column matches; reverts if there is no such row.
    function findManifestRowByName(string memory path, Kind kind, string memory name)
        internal
        returns (Row memory)
    {
        Row[] memory rows = readManifestRows(path, kind);
        for (uint256 i = 0; i < rows.length; i++) {
            if (keccak256(bytes(rows[i].name)) == keccak256(bytes(name))) return rows[i];
        }
        revert("no manifest row with that name");
    }

    function firstRow(string memory path, Kind kind) internal returns (Row memory) {
        Row[] memory rows = readManifestRows(path, kind);
        require(rows.length > 0, "no manifest row for kind");
        return rows[0];
    }

    /// A representative valid step log for happy-path and tampering tests, with its manifest
    /// row (before/after roots, cycle count). Any recorded cycle would serve equally; this
    /// returns the first program's first cycle. Callers must not depend on which one.
    function sampleStepLog() internal returns (bytes memory log, Row memory row) {
        string[] memory dirs = programDirs();
        require(dirs.length > 0, "no per-cycle uarch fixtures");
        row = firstRow(string.concat(dirs[0], "/_manifest.csv"), Kind.Cycle);
        log = vm.readFileBinary(string.concat(dirs[0], "/", row.name));
    }

    function parseRow(string memory line) internal pure returns (Row memory r) {
        string[] memory cols = vm.split(line, ",");
        require(cols.length == 11, "manifest row must have 11 columns");
        r.kind = parseKind(cols[0]);
        r.name = cols[1];
        r.expectError = cols[2];
        // cols[3] is the hash function name; unused by the verifier tests.
        r.requestedCycleCount = uint64(vm.parseUint(cols[4]));
        r.rootHashBefore = vm.parseBytes32(cols[5]);
        r.rootHashAfter = vm.parseBytes32(cols[6]);
        if (bytes(cols[7]).length > 0) r.reason = uint16(vm.parseUint(cols[7]));
        if (bytes(cols[8]).length > 0) r.dataLength = uint32(vm.parseUint(cols[8]));
        r.data = bytes(cols[9]);
        if (r.data.length != r.dataLength && r.dataLength > 0) {
            r.data = expandPayload(r.data, r.dataLength);
        }
        if (bytes(cols[10]).length > 0) r.revertRootHash = vm.parseBytes32(cols[10]);
    }

    function parseKind(string memory s) private pure returns (Kind) {
        bytes32 h = keccak256(bytes(s));
        if (h == keccak256(bytes("cycle"))) return Kind.Cycle;
        if (h == keccak256(bytes("reset_uarch"))) return Kind.ResetUarch;
        if (h == keccak256(bytes("send_cmio_response"))) return Kind.SendCmioResponse;
        return Kind.Unknown;
    }

    /// Expands a payload repeat unit to dataLength bytes by doubling the filled prefix
    /// (word-wise copies; the trailing partial word stays inside the array's padded slot).
    function expandPayload(bytes memory unit, uint256 length)
        internal
        pure
        returns (bytes memory out)
    {
        require(unit.length > 0, "manifest: empty data unit with nonzero dataLength");
        out = new bytes(length);
        uint256 filled = unit.length < length ? unit.length : length;
        for (uint256 i = 0; i < filled; i++) {
            out[i] = unit[i];
        }
        while (filled < length) {
            uint256 chunk = filled <= length - filled ? filled : length - filled;
            assembly ("memory-safe") {
                let src := add(out, 32)
                let dst := add(add(out, 32), filled)
                for { let off := 0 } lt(off, chunk) { off := add(off, 32) } {
                    mstore(add(dst, off), mload(add(src, off)))
                }
            }
            filled += chunk;
        }
    }
}
