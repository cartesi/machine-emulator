#!/bin/bash
# HARNESS WORKAROUND (not part of machine-solidity-step v0.17.0-test1, applied only to the separately labelled
# variant work/solidity-step/regenerated-patched): the uarch-step.cpp of audit/prt2 checks
# `set_index >= TLB_NUM_SETS` in the write-TLB ecall; the step translator prefixes only the constants it finds in
# EmulatorConstants.sol, and neither the template nor generate_EmulatorConstants.lua defines TLB_NUM_SETS, so the
# regenerated UArchStep.sol does not compile ("Undeclared identifier"). Add the constant to the template next to
# TLB_SET_SIZE, with the value of the emulator's Lua module (cartesi.TLB_NUM_SETS, = CM_TLB_NUM_SETS in cm.h).
set -euo pipefail
v=$(lua5.4 -e 'io.write(require("cartesi").TLB_NUM_SETS)')
grep -q 'TLB_NUM_SETS' templates/EmulatorConstants.sol.template && exit 0
sed -i "s/^\(    uint64 constant TLB_SET_SIZE = 256;\)\$/\1\n    uint64 constant TLB_NUM_SETS = $v;/" templates/EmulatorConstants.sol.template
grep -q "TLB_NUM_SETS = $v" templates/EmulatorConstants.sol.template
echo "workaround 01-tlb-num-sets: added 'uint64 constant TLB_NUM_SETS = $v;' to templates/EmulatorConstants.sol.template"
