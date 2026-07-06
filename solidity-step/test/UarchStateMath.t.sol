// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {StateAccess} from "src/StateAccess.sol";

/// Unit tests for the math helpers in StateAccess (the transpiler bridge
/// mirroring machine-emulator/src/uarch-solidity-compat.hpp).
contract UarchStateMathTest is Test {
    int16 constant INT16_MAX = type(int16).max;
    int32 constant INT32_MAX = type(int32).max;
    int64 constant INT64_MAX = type(int64).max;
    int16 constant INT16_MIN = type(int16).min;
    int32 constant INT32_MIN = type(int32).min;
    int64 constant INT64_MIN = type(int64).min;
    uint16 constant UINT16_MAX = type(uint16).max;
    uint32 constant UINT32_MAX = type(uint32).max;
    uint64 constant UINT64_MAX = type(uint64).max;

    function testSanity() public pure {
        assertEq(UINT16_MAX, 65535);
        assertEq(UINT32_MAX, 4294967295);
        assertEq(UINT64_MAX, 18446744073709551615);
        assertEq(INT16_MAX, 32767);
        assertEq(INT32_MAX, 2147483647);
        assertEq(INT64_MAX, 9223372036854775807);
        assertEq(INT16_MIN, -32768);
        assertEq(INT32_MIN, -INT32_MAX - 1);
        assertEq(INT64_MIN, -INT64_MAX - 1);
    }

    function testUint64ToInt32() public pure {
        assertEq(StateAccess.uint64ToInt32(1), 1);
        assertEq(StateAccess.uint64ToInt32(0xffffffff), -1);
        assertEq(StateAccess.uint64ToInt32(0xffffffff << 31), INT32_MIN);
        assertEq(StateAccess.uint64ToInt32(0xffffffff << 32), 0);
    }

    function testUint64AddInt32() public pure {
        assertEq(StateAccess.uint64AddInt32(2, -1), 1);
        assertEq(StateAccess.uint64AddInt32(0, -1), UINT64_MAX);
        assertEq(StateAccess.uint64AddInt32(UINT64_MAX, 1), 0);
    }

    function testUint64SubUint64() public pure {
        assertEq(StateAccess.uint64SubUint64(1, 1), 0);
        assertEq(StateAccess.uint64SubUint64(0, 1), UINT64_MAX);
    }

    function testUint64AddUint64() public pure {
        assertEq(StateAccess.uint64AddUint64(0, 1), 1);
        assertEq(StateAccess.uint64AddUint64(UINT64_MAX, 1), 0);
    }

    function testUint64ShiftRight() public pure {
        assertEq(StateAccess.uint64ShiftRight(0, 0), 0);
        assertEq(StateAccess.uint64ShiftRight(0, 1), 0);
        assertEq(StateAccess.uint64ShiftRight(4, 1), 2);
        assertEq(StateAccess.uint64ShiftRight(4, 2), 1);
        assertEq(StateAccess.uint64ShiftRight(4, 3), 0);
        assertEq(StateAccess.uint64ShiftRight(UINT64_MAX, 63), 1);
    }

    function testUint64ShiftLeft() public pure {
        assertEq(StateAccess.uint64ShiftLeft(0, 0), 0);
        assertEq(StateAccess.uint64ShiftLeft(0, 1), 0);
        assertEq(StateAccess.uint64ShiftLeft(4, 1), 8);
        assertEq(StateAccess.uint64ShiftLeft(4, 2), 16);
        assertEq(StateAccess.uint64ShiftLeft(UINT64_MAX, 63), 1 << 63);
    }

    function testInt64ShiftRight() public pure {
        assertEq(StateAccess.int64ShiftRight(0, 0), 0);
        assertEq(StateAccess.int64ShiftRight(0, 1), 0);
        assertEq(StateAccess.int64ShiftRight(4, 1), 2);
        assertEq(StateAccess.int64ShiftRight(4, 2), 1);
        assertEq(StateAccess.int64ShiftRight(4, 3), 0);
        assertEq(StateAccess.int64ShiftRight(INT64_MAX, 62), 1);
        assertEq(StateAccess.int64ShiftRight(INT64_MAX, 63), 0);
        assertEq(StateAccess.int64ShiftRight(-1, 1), -1);
        assertEq(StateAccess.int64ShiftRight(-4, 1), -2);
        assertEq(StateAccess.int64ShiftRight(INT64_MIN, 62), -2);
        assertEq(StateAccess.int64ShiftRight(INT64_MIN, 63), -1);
    }

    function testInt64AddInt64() public pure {
        assertEq(StateAccess.int64AddInt64(0, 0), 0);
        assertEq(StateAccess.int64AddInt64(0, 1), 1);
        assertEq(StateAccess.int64AddInt64(0, -1), -1);
        assertEq(StateAccess.int64AddInt64(-1, 0), -1);
        assertEq(StateAccess.int64AddInt64(INT64_MAX, 1), INT64_MIN);
        assertEq(StateAccess.int64AddInt64(INT64_MAX, INT64_MAX), -2);
    }

    function testUint32ShiftRight() public pure {
        assertEq(StateAccess.uint32ShiftRight(0, 0), 0);
        assertEq(StateAccess.uint32ShiftRight(0, 1), 0);
        assertEq(StateAccess.uint32ShiftRight(4, 1), 2);
        assertEq(StateAccess.uint32ShiftRight(4, 2), 1);
        assertEq(StateAccess.uint32ShiftRight(4, 3), 0);
        assertEq(StateAccess.uint32ShiftRight(UINT32_MAX, 31), 1);
    }

    function testUint32ShiftLeft() public pure {
        assertEq(StateAccess.uint32ShiftLeft(0, 0), 0);
        assertEq(StateAccess.uint32ShiftLeft(0, 1), 0);
        assertEq(StateAccess.uint32ShiftLeft(4, 1), 8);
        assertEq(StateAccess.uint32ShiftLeft(4, 2), 16);
        assertEq(StateAccess.uint32ShiftLeft(4, 3), 32);
        assertEq(StateAccess.uint32ShiftLeft(UINT32_MAX, 31), 0x80000000);
    }

    function testInt32ToUint64() public pure {
        assertEq(StateAccess.int32ToUint64(1), 1);
        assertEq(StateAccess.int32ToUint64(INT32_MAX), 2147483647);
        assertEq(StateAccess.int32ToUint64(INT32_MIN), 0xffffffff80000000);
    }

    function testInt32ShiftRight() public pure {
        assertEq(StateAccess.int32ShiftRight(0, 0), 0);
        assertEq(StateAccess.int32ShiftRight(0, 1), 0);
        assertEq(StateAccess.int32ShiftRight(4, 1), 2);
        assertEq(StateAccess.int32ShiftRight(4, 2), 1);
        assertEq(StateAccess.int32ShiftRight(4, 3), 0);
        assertEq(StateAccess.int32ShiftRight(INT32_MAX, 30), 1);
        assertEq(StateAccess.int32ShiftRight(INT32_MAX, 31), 0);
        assertEq(StateAccess.int32ShiftRight(-1, 1), -1);
        assertEq(StateAccess.int32ShiftRight(-4, 1), -2);
        assertEq(StateAccess.int32ShiftRight(INT32_MIN, 30), -2);
        assertEq(StateAccess.int32ShiftRight(INT32_MIN, 31), -1);
    }

    function testInt32AddInt32() public pure {
        assertEq(StateAccess.int32AddInt32(0, 0), 0);
        assertEq(StateAccess.int32AddInt32(0, 1), 1);
        assertEq(StateAccess.int32AddInt32(0, -1), -1);
        assertEq(StateAccess.int32AddInt32(-1, 0), -1);
        assertEq(StateAccess.int32AddInt32(INT32_MAX, 1), INT32_MIN);
        assertEq(StateAccess.int32AddInt32(INT32_MAX, INT32_MAX), -2);
    }

    function testInt32SubInt32() public pure {
        assertEq(StateAccess.int32SubInt32(1, 1), 0);
        assertEq(StateAccess.int32SubInt32(1, 0), 1);
        assertEq(StateAccess.int32SubInt32(0, 1), -1);
        assertEq(StateAccess.int32SubInt32(-1, -1), 0);
        assertEq(StateAccess.int32SubInt32(INT32_MIN, INT32_MAX), 1);
        assertEq(StateAccess.int32SubInt32(INT32_MAX, INT32_MIN), -1);
    }

    function testInt16ToUint64() public pure {
        assertEq(StateAccess.int16ToUint64(1), 1);
        assertEq(StateAccess.int16ToUint64(INT16_MAX), 32767);
        assertEq(StateAccess.int16ToUint64(INT16_MIN), 0xffffffffffff8000);
    }

    function testInt8ToUint64() public pure {
        assertEq(StateAccess.int8ToUint64(int8(1)), 1);
        assertEq(StateAccess.int8ToUint64(int8(127)), 127);
        assertEq(StateAccess.int8ToUint64(int8(-128)), 0xffffffffffffff80);
    }

    function testUint32Log2() public pure {
        assertEq(StateAccess.uint32Log2(1), 0);
        assertEq(StateAccess.uint32Log2(2), 1);
        assertEq(StateAccess.uint32Log2(3), 1);
        assertEq(StateAccess.uint32Log2(4), 2);
        assertEq(StateAccess.uint32Log2(5), 2);
        assertEq(StateAccess.uint32Log2(0x7fffffff), 30);
        assertEq(StateAccess.uint32Log2(0x80000000), 31);
        assertEq(StateAccess.uint32Log2(0xffffffff), 31);
    }

    function testUint32Log2OfZeroReverts() public {
        vm.expectRevert(StateAccess.Uint32Log2OfZero.selector);
        this.externalUint32Log2(0);
    }

    /// External wrapper so vm.expectRevert sees a CALL boundary (internal library
    /// calls inline, so the revert would otherwise hit the test method itself).
    function externalUint32Log2(uint32 v) external pure returns (uint32) {
        return StateAccess.uint32Log2(v);
    }
}
