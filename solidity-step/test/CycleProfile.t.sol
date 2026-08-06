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

import {Test, console} from "forge-std/Test.sol";

import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";
import {UArchStep} from "src/UArchStep.sol";

/// Per-instruction gas attribution for a whole-mcycle log: replays it through
/// UArchStep bracketing every cycle with gasleft and bucketing by the executed
/// instruction's opcode+funct3, so interpreter optimization targets the measured
/// hot instructions instead of guesses. Skips silently when MCYCLE_PROFILE_LOG is
/// unset. Usage:
///   MCYCLE_PROFILE_LOG=test/fixtures/worst-mcycle-rvc.log \
///     forge test --match-contract CycleProfile -vv
contract CycleProfileTest is Test {
    uint256 constant MAX_MCYCLE_CYCLES = 1 << 21;

    function testCycleProfile() public view {
        string memory path = vm.envOr("MCYCLE_PROFILE_LOG", string(""));
        if (bytes(path).length == 0) return;
        this.profile(vm.readFileBinary(path));
    }

    function profile(bytes calldata log) external view {
        StepLog.Context memory ctx = StepLog.decode(log);
        // bucket key = opcode | funct3 << 7 (fits 10 bits); JAL/LUI/AUIPC have no
        // funct3 but their opcodes are unique, so collisions cannot merge distinct
        // instructions of this ISA
        uint256[] memory count = new uint256[](1024);
        uint256[] memory gasUsed = new uint256[](1024);
        uint256 cycles;
        while (true) {
            uint64 pc = StateAccess.readPc(ctx);
            // fetch the 4-byte insn out of the aligned 8-byte little-endian word
            uint64 word = StateAccess.readWord(ctx, pc & ~uint64(7));
            uint32 insn = (pc & 4) != 0 ? uint32(word >> 32) : uint32(word);
            uint256 key = (insn & 0x7f) | (((insn >> 12) & 7) << 7);
            uint256 g0 = gasleft();
            if (UArchStep.uarchStep(ctx) != UArchStep.UArchStepStatus.Success) break;
            gasUsed[key] += g0 - gasleft();
            count[key]++;
            cycles++;
            require(cycles <= MAX_MCYCLE_CYCLES, "runaway replay");
        }
        uint256 fmp;
        assembly ("memory-safe") {
            fmp := mload(0x40)
        }
        console.log(string.concat("cycles ", vm.toString(cycles)));
        console.log(
            string.concat(
                "memory high-water ",
                vm.toString(fmp),
                " (",
                vm.toString(fmp / (cycles == 0 ? 1 : cycles)),
                " bytes/cycle amortized)"
            )
        );
        for (uint256 key = 0; key < 1024; key++) {
            if (count[key] == 0) continue;
            console.log(
                string.concat(
                    "opcode 0x",
                    toHex(key & 0x7f),
                    " funct3 ",
                    vm.toString(key >> 7),
                    "  count ",
                    vm.toString(count[key]),
                    "  avg ",
                    vm.toString(gasUsed[key] / count[key]),
                    "  total ",
                    vm.toString(gasUsed[key])
                )
            );
        }
    }

    function toHex(uint256 v) private pure returns (string memory) {
        bytes16 digits = "0123456789abcdef";
        return string(abi.encodePacked(digits[(v >> 4) & 0xf], digits[v & 0xf]));
    }
}
