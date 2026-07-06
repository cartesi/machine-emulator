#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0
--
-- Golden-output unit tests for tools/transpile-uarch.lua. Each test feeds a
-- small synthetic C++ blob into the transpiler and asserts the output
-- (whitespace-normalised) matches a hand-written expected Solidity blob.
--
-- Run from solidity-step/ via: lua5.4 tools/test-transpile-uarch.lua
-- The transpiler reads ../../src/uarch-solidity-compat.hpp and
-- src/EmulatorConstants.sol from disk to know which names to prefix, so the
-- test must be invoked with solidity-step/ as the working directory.

package.path = "tools/?.lua;" .. package.path
local gen = require("transpile-uarch")

local pass, fail = 0, 0

local function test(name, fn)
    local ok, err = pcall(fn)
    if ok then
        pass = pass + 1
    else
        fail = fail + 1
        io.stderr:write("FAIL: " .. name .. "\n  " .. tostring(err) .. "\n")
    end
end

local function normalize(s)
    -- Strip // comments and collapse whitespace so test assertions are robust
    -- to formatting churn in the transpiler's output.
    s = s:gsub("//[^\n]*", "")
    s = s:gsub("%s+", " ")
    s = s:gsub("^ ", ""):gsub(" $", "")
    return s
end

local function assert_transpiles(input_cpp, input_h, lib, entry, expected_sol)
    local result = gen.transpile(input_cpp, input_h, lib, entry)
    local actual = normalize(result:sub(#gen.LICENSE_BANNER + 1))
    local expected = normalize(expected_sol)
    assert(actual == expected,
        "\nexpected:\n" .. expected .. "\n\ngot:\n" .. actual)
end


test("uarch-step: templates stripped, STATE access prefixed, UINT64_MAX rewritten", function()
    local input_cpp = [==[
        // Copyright Cartesi and individual authors (see AUTHORS)
        // SPDX-License-Identifier: LGPL-3.0-or-later

        #include "uarch-step.h"
        #include "uarch-record-step-state-access.h"
        #include "uarch-solidity-compat.h"

        // NOLINTBEGIN(google-readability-casting,misc-const-correctness)
        namespace cartesi {

        template  < typename UarchState >
        static  inline  uint64 readUint64(const  UarchState  a, uint64 paddr) {
            return readWord(a, paddr);
        }

        template <typename UarchState>
        UArchStepStatus uarch_step(const	UarchState a) {
            uint64 cycle = readCycle(a);
            if (cycle >= UINT64_MAX) {
                return UArchStepStatus::CycleOverflow;
            }
        }

        // Explicit instantiation for uarch_state_access
        template UArchStepStatus uarch_step(const uarch_state_access a);
        }
        // NOLINTEND(google-readability-casting,misc-const-correctness)
    ]==]
    local input_h = "enum class UArchStepStatus : int { Success, CycleOverflow, UArchHalted };"

    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library UArchStep {
            enum UArchStepStatus { Success, CycleOverflow, UArchHalted }

            function readUint64(StepLog.Context memory a, uint64 paddr) private pure returns (uint64) {
                return StateAccess.readWord(a, paddr);
            }

            function uarchStep(StepLog.Context memory a) internal pure returns (UArchStepStatus) {
                uint64 cycle = StateAccess.readCycle(a);
                if (cycle >= type(uint64).max) {
                    return UArchStepStatus.CycleOverflow;
                }
            }
        }
    ]=]

    assert_transpiles(input_cpp, input_h, "UArchStep", "uarchStep", expected_sol)
end)


test("uarch-reset-state: 'UarchState &a' reference form, entrypoint rename", function()
    local input_cpp = [==[
        // Copyright Cartesi and individual authors (see AUTHORS)
        // SPDX-License-Identifier: LGPL-3.0-or-later

        namespace cartesi {

        template <typename UarchState>
        void uarch_reset_state(UarchState &a) {
            resetState(a);
        }

        template void uarch_reset_state(uarch_state_access &a);
        }
    ]==]

    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library UArchReset {

            function uarchResetState(StepLog.Context memory a) internal pure {
                StateAccess.resetState(a);
            }
        }
    ]=]

    assert_transpiles(input_cpp, nil, "UArchReset", "uarchResetState", expected_sol)
end)


test("send-cmio-response: bytes32 passes through, bytes data to calldata, constants prefixed", function()
    local input_cpp = [==[
        // Copyright Cartesi and individual authors (see AUTHORS)
        // SPDX-License-Identifier: LGPL-3.0-or-later

        namespace cartesi {

        template <typename STATE_ACCESS>
        void send_cmio_response(STATE_ACCESS a, bytes32 revertRootHash, uint16 reason, bytes data, uint32 dataLength) {
            writeRevertRootHash(a, revertRootHash);
            if (dataLength > 0) {
                uint32 writeLengthLog2Size = uint32Log2(dataLength);
                writeMemoryWithPadding(a, AR_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size);
            }
            throwRuntimeError(a, "CMIO response data is too large");
            writeHtifFromhost(a, 0);
            writeIflagsY(a, 0);
        }

        template void send_cmio_response(state_access a, bytes32 revertRootHash, uint16_t reason, const unsigned char *data, uint32 length);
        }
    ]==]

    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library SendCmioResponse {

            function sendCmioResponse(StepLog.Context memory a, bytes32 revertRootHash, uint16, bytes calldata data, uint32 dataLength) internal pure {
                StateAccess.writeRevertRootHash(a, revertRootHash);
                if (dataLength > 0) {
                    uint32 writeLengthLog2Size = StateAccess.uint32Log2(dataLength);
                    StateAccess.writeMemoryWithPadding(a, EmulatorConstants.AR_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size);
                }
                StateAccess.throwRuntimeError(a, "CMIO response data is too large");
                StateAccess.writeHtifFromhost(a, 0);
                StateAccess.writeIflagsY(a, 0);
            }
        }
    ]=]

    assert_transpiles(input_cpp, nil, "SendCmioResponse", "sendCmioResponse", expected_sol)
end)


test("namespace body: a brace inside a string literal does not truncate the output", function()
    local input_cpp = [==[
        namespace cartesi {
        template <typename UarchState>
        void f(const UarchState a) {
            throwRuntimeError(a, "unbalanced } brace");
            writeIflagsY(a, 0);
        }
        }
    ]==]
    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library UArchStep {
            function f(StepLog.Context memory a) private pure {
                StateAccess.throwRuntimeError(a, "unbalanced } brace");
                StateAccess.writeIflagsY(a, 0);
            }
        }
    ]=]
    assert_transpiles(input_cpp, nil, "UArchStep", "uarch_step", expected_sol)
end)


test("strip: a semicolon inside a string literal does not end the stripped statement early", function()
    local input_cpp = [==[
        namespace cartesi {
        static inline void g(const UarchState a) {
            [[maybe_unused]] auto note = dumpInsn(a, "has ; semicolon");
            throwRuntimeError(a, "kept");
        }
        }
    ]==]
    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library UArchStep {
            function g(StepLog.Context memory a) private pure {
                StateAccess.throwRuntimeError(a, "kept");
            }
        }
    ]=]
    assert_transpiles(input_cpp, nil, "UArchStep", "uarch_step", expected_sol)
end)


test("params left unused after stripping a debug line get their names blanked", function()
    -- dumpInsn is stripped via [[maybe_unused]]; insn and pc are used only there, so their
    -- names are blanked while their types stay. a is used, so it keeps its name.
    local input_cpp = [==[
        namespace cartesi {
        static inline void executeEBREAK(const UarchState a, uint32 insn, uint64 pc) {
            [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "ebreak");
            throwRuntimeError(a, "uarch aborted");
        }
        }
    ]==]
    local expected_sol = [=[
        pragma solidity ^0.8.30;

        import {StepLog}           from "src/StepLog.sol";
        import {StateAccess}        from "src/StateAccess.sol";
        import {EmulatorConstants} from "src/EmulatorConstants.sol";

        library UArchStep {
            function executeEBREAK(StepLog.Context memory a, uint32, uint64) private pure {
                StateAccess.throwRuntimeError(a, "uarch aborted");
            }
        }
    ]=]
    assert_transpiles(input_cpp, nil, "UArchStep", "uarch_step", expected_sol)
end)


local function assert_rejects(input_cpp, msg_substring)
    local ok, err = pcall(gen.transpile, input_cpp, nil, "Lib", "entry")
    assert(not ok, "expected transpile to reject the input, but it succeeded")
    assert(tostring(err):find(msg_substring, 1, true),
        "error did not mention '" .. msg_substring .. "':\n  " .. tostring(err))
end


test("dialect guard: rejects a raw shift on a non-literal operand", function()
    assert_rejects([==[
        namespace cartesi {
        template <typename UarchState>
        uint64 f(UarchState a) {
            return readWord(a) << 3;
        }
        }
    ]==], "raw shift")
end)


test("dialect guard: rejects a native fixed-width C++ type", function()
    assert_rejects([==[
        namespace cartesi {
        template <typename UarchState>
        void f(UarchState a) {
            uint32_t x = readWord(a);
        }
        }
    ]==], "native C++ type")
end)


print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then os.exit(1) end
