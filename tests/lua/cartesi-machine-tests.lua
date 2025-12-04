#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local cartesi = require("cartesi")
local util = require("cartesi.util")
local test_util = require("cartesi.tests.util")
local tabular = require("cartesi.tabular")
local parallel = require("cartesi.parallel")
local jsonrpc

-- Tests Cases
-- format {"ram_image_file", number_of_cycles, halt_payload}
local riscv_tests = {
    { "rv64mi-p-breakpoint.bin", 122 },
    { "rv64mi-p-csr.bin", 281 },
    { "rv64mi-p-illegal.bin", 361 },
    { "rv64mi-p-instret_overflow.bin", 98 },
    { "rv64mi-p-ld-misaligned.bin", 369 },
    { "rv64mi-p-lh-misaligned.bin", 121 },
    { "rv64mi-p-lw-misaligned.bin", 181 },
    { "rv64mi-p-ma_addr.bin", 744 },
    { "rv64mi-p-ma_fetch.bin", 127 },
    { "rv64mi-p-mcsr.bin", 103 },
    { "rv64mi-p-sbreak.bin", 111 },
    { "rv64mi-p-scall.bin", 95 },
    { "rv64mi-p-sd-misaligned.bin", 389 },
    { "rv64mi-p-sh-misaligned.bin", 129 },
    { "rv64mi-p-sw-misaligned.bin", 185 },
    { "rv64mi-p-zicntr.bin", 120 },
    { "rv64si-p-csr.bin", 196 },
    { "rv64si-p-dirty.bin", 177 },
    { "rv64si-p-icache-alias.bin", 227 },
    { "rv64si-p-ma_fetch.bin", 125 },
    { "rv64si-p-sbreak.bin", 105 },
    { "rv64si-p-scall.bin", 112 },
    { "rv64si-p-wfi.bin", 91 },
    { "rv64ua-p-amoadd_d.bin", 108 },
    { "rv64ua-p-amoadd_w.bin", 105 },
    { "rv64ua-p-amoand_d.bin", 105 },
    { "rv64ua-p-amoand_w.bin", 104 },
    { "rv64ua-p-amomax_d.bin", 104 },
    { "rv64ua-p-amomax_w.bin", 118 },
    { "rv64ua-p-amomaxu_d.bin", 104 },
    { "rv64ua-p-amomaxu_w.bin", 118 },
    { "rv64ua-p-amomin_d.bin", 104 },
    { "rv64ua-p-amomin_w.bin", 118 },
    { "rv64ua-p-amominu_d.bin", 104 },
    { "rv64ua-p-amominu_w.bin", 118 },
    { "rv64ua-p-amoor_d.bin", 103 },
    { "rv64ua-p-amoor_w.bin", 103 },
    { "rv64ua-p-amoswap_d.bin", 105 },
    { "rv64ua-p-amoswap_w.bin", 104 },
    { "rv64ua-p-amoxor_d.bin", 106 },
    { "rv64ua-p-amoxor_w.bin", 108 },
    { "rv64ua-p-lrsc.bin", 6282 },
    { "rv64ua-v-amoadd_d.bin", 13282 },
    { "rv64ua-v-amoadd_w.bin", 13279 },
    { "rv64ua-v-amoand_d.bin", 13291 },
    { "rv64ua-v-amoand_w.bin", 13290 },
    { "rv64ua-v-amomax_d.bin", 13272 },
    { "rv64ua-v-amomax_w.bin", 13286 },
    { "rv64ua-v-amomaxu_d.bin", 13272 },
    { "rv64ua-v-amomaxu_w.bin", 13286 },
    { "rv64ua-v-amomin_d.bin", 13272 },
    { "rv64ua-v-amomin_w.bin", 13304 },
    { "rv64ua-v-amominu_d.bin", 13278 },
    { "rv64ua-v-amominu_w.bin", 13292 },
    { "rv64ua-v-amoor_d.bin", 13271 },
    { "rv64ua-v-amoor_w.bin", 13271 },
    { "rv64ua-v-amoswap_d.bin", 13291 },
    { "rv64ua-v-amoswap_w.bin", 13290 },
    { "rv64ua-v-amoxor_d.bin", 13274 },
    { "rv64ua-v-amoxor_w.bin", 13276 },
    { "rv64ua-v-lrsc.bin", 19450 },
    { "rv64uc-p-rvc.bin", 299 },
    { "rv64uc-v-rvc.bin", 19360 },
    { "rv64ud-p-fadd.bin", 214 },
    { "rv64ud-p-fclass.bin", 157 },
    { "rv64ud-p-fcmp.bin", 264 },
    { "rv64ud-p-fcvt.bin", 196 },
    { "rv64ud-p-fcvt_w.bin", 614 },
    { "rv64ud-p-fdiv.bin", 188 },
    { "rv64ud-p-fmadd.bin", 240 },
    { "rv64ud-p-fmin.bin", 318 },
    { "rv64ud-p-ldst.bin", 129 },
    { "rv64ud-p-move.bin", 1034 },
    { "rv64ud-p-recoding.bin", 142 },
    { "rv64ud-p-structural.bin", 207 },
    { "rv64ud-v-fadd.bin", 13869 },
    { "rv64ud-v-fclass.bin", 7947 },
    { "rv64ud-v-fcmp.bin", 13919 },
    { "rv64ud-v-fcvt.bin", 13851 },
    { "rv64ud-v-fcvt_w.bin", 20134 },
    { "rv64ud-v-fdiv.bin", 13843 },
    { "rv64ud-v-fmadd.bin", 13895 },
    { "rv64ud-v-fmin.bin", 13973 },
    { "rv64ud-v-ldst.bin", 13305 },
    { "rv64ud-v-move.bin", 14689 },
    { "rv64ud-v-recoding.bin", 13348 },
    { "rv64ud-v-structural.bin", 7997 },
    { "rv64uf-p-fadd.bin", 214 },
    { "rv64uf-p-fclass.bin", 151 },
    { "rv64uf-p-fcmp.bin", 264 },
    { "rv64uf-p-fcvt.bin", 156 },
    { "rv64uf-p-fcvt_w.bin", 554 },
    { "rv64uf-p-fdiv.bin", 175 },
    { "rv64uf-p-fmadd.bin", 240 },
    { "rv64uf-p-fmin.bin", 318 },
    { "rv64uf-p-ldst.bin", 110 },
    { "rv64uf-p-move.bin", 259 },
    { "rv64uf-p-recoding.bin", 117 },
    { "rv64uf-v-fadd.bin", 13869 },
    { "rv64uf-v-fclass.bin", 7941 },
    { "rv64uf-v-fcmp.bin", 13919 },
    { "rv64uf-v-fcvt.bin", 13811 },
    { "rv64uf-v-fcvt_w.bin", 20074 },
    { "rv64uf-v-fdiv.bin", 13830 },
    { "rv64uf-v-fmadd.bin", 13895 },
    { "rv64uf-v-fmin.bin", 13973 },
    { "rv64uf-v-ldst.bin", 13310 },
    { "rv64uf-v-move.bin", 8049 },
    { "rv64uf-v-recoding.bin", 13772 },
    { "rv64ui-p-add.bin", 509 },
    { "rv64ui-p-addi.bin", 284 },
    { "rv64ui-p-addiw.bin", 281 },
    { "rv64ui-p-addw.bin", 504 },
    { "rv64ui-p-and.bin", 584 },
    { "rv64ui-p-andi.bin", 255 },
    { "rv64ui-p-auipc.bin", 98 },
    { "rv64ui-p-beq.bin", 330 },
    { "rv64ui-p-bge.bin", 348 },
    { "rv64ui-p-bgeu.bin", 438 },
    { "rv64ui-p-blt.bin", 330 },
    { "rv64ui-p-bltu.bin", 416 },
    { "rv64ui-p-bne.bin", 330 },
    { "rv64ui-p-fence_i.bin", 338 },
    { "rv64ui-p-jal.bin", 94 },
    { "rv64ui-p-jalr.bin", 154 },
    { "rv64ui-p-lb.bin", 292 },
    { "rv64ui-p-lbu.bin", 292 },
    { "rv64ui-p-ld.bin", 474 },
    { "rv64ui-p-ld_st.bin", 1454 },
    { "rv64ui-p-lh.bin", 308 },
    { "rv64ui-p-lhu.bin", 317 },
    { "rv64ui-p-lui.bin", 104 },
    { "rv64ui-p-lw.bin", 322 },
    { "rv64ui-p-lwu.bin", 356 },
    { "rv64ui-p-or.bin", 617 },
    { "rv64ui-p-ori.bin", 248 },
    { "rv64ui-p-sb.bin", 493 },
    { "rv64ui-p-sd.bin", 665 },
    { "rv64ui-p-sh.bin", 546 },
    { "rv64ui-p-simple.bin", 80 },
    { "rv64ui-p-sll.bin", 579 },
    { "rv64ui-p-slli.bin", 309 },
    { "rv64ui-p-slliw.bin", 316 },
    { "rv64ui-p-sllw.bin", 579 },
    { "rv64ui-p-slt.bin", 498 },
    { "rv64ui-p-slti.bin", 276 },
    { "rv64ui-p-sltiu.bin", 276 },
    { "rv64ui-p-sltu.bin", 515 },
    { "rv64ui-p-sra.bin", 551 },
    { "rv64ui-p-srai.bin", 297 },
    { "rv64ui-p-sraiw.bin", 343 },
    { "rv64ui-p-sraw.bin", 591 },
    { "rv64ui-p-srl.bin", 593 },
    { "rv64ui-p-srli.bin", 318 },
    { "rv64ui-p-srliw.bin", 325 },
    { "rv64ui-p-srlw.bin", 585 },
    { "rv64ui-p-st_ld.bin", 764 },
    { "rv64ui-p-sub.bin", 500 },
    { "rv64ui-p-subw.bin", 496 },
    { "rv64ui-p-sw.bin", 553 },
    { "rv64ui-p-xor.bin", 612 },
    { "rv64ui-p-xori.bin", 246 },
    { "rv64ui-v-add.bin", 8301 },
    { "rv64ui-v-addi.bin", 8076 },
    { "rv64ui-v-addiw.bin", 8073 },
    { "rv64ui-v-addw.bin", 8296 },
    { "rv64ui-v-and.bin", 14241 },
    { "rv64ui-v-andi.bin", 8047 },
    { "rv64ui-v-auipc.bin", 7889 },
    { "rv64ui-v-beq.bin", 8122 },
    { "rv64ui-v-bge.bin", 8139 },
    { "rv64ui-v-bgeu.bin", 8230 },
    { "rv64ui-v-blt.bin", 8122 },
    { "rv64ui-v-bltu.bin", 8208 },
    { "rv64ui-v-bne.bin", 8122 },
    { "rv64ui-v-fence_i.bin", 13535 },
    { "rv64ui-v-jal.bin", 7886 },
    { "rv64ui-v-jalr.bin", 7946 },
    { "rv64ui-v-lb.bin", 13949 },
    { "rv64ui-v-lbu.bin", 13949 },
    { "rv64ui-v-ld.bin", 14131 },
    { "rv64ui-v-ld_st.bin", 26352 },
    { "rv64ui-v-lh.bin", 13965 },
    { "rv64ui-v-lhu.bin", 13974 },
    { "rv64ui-v-lui.bin", 7896 },
    { "rv64ui-v-lw.bin", 13979 },
    { "rv64ui-v-lwu.bin", 14013 },
    { "rv64ui-v-or.bin", 14274 },
    { "rv64ui-v-ori.bin", 8040 },
    { "rv64ui-v-sb.bin", 13661 },
    { "rv64ui-v-sd.bin", 19698 },
    { "rv64ui-v-sh.bin", 13714 },
    { "rv64ui-v-simple.bin", 7872 },
    { "rv64ui-v-sll.bin", 14236 },
    { "rv64ui-v-slli.bin", 8101 },
    { "rv64ui-v-slliw.bin", 8108 },
    { "rv64ui-v-sllw.bin", 14236 },
    { "rv64ui-v-slt.bin", 8290 },
    { "rv64ui-v-slti.bin", 8068 },
    { "rv64ui-v-sltiu.bin", 8068 },
    { "rv64ui-v-sltu.bin", 8307 },
    { "rv64ui-v-sra.bin", 14208 },
    { "rv64ui-v-srai.bin", 8089 },
    { "rv64ui-v-sraiw.bin", 8135 },
    { "rv64ui-v-sraw.bin", 14248 },
    { "rv64ui-v-srl.bin", 14250 },
    { "rv64ui-v-srli.bin", 8110 },
    { "rv64ui-v-srliw.bin", 8117 },
    { "rv64ui-v-srlw.bin", 14242 },
    { "rv64ui-v-st_ld.bin", 19797 },
    { "rv64ui-v-sub.bin", 8292 },
    { "rv64ui-v-subw.bin", 8288 },
    { "rv64ui-v-sw.bin", 13721 },
    { "rv64ui-v-xor.bin", 14269 },
    { "rv64ui-v-xori.bin", 8038 },
    { "rv64um-p-div.bin", 148 },
    { "rv64um-p-divu.bin", 146 },
    { "rv64um-p-divuw.bin", 138 },
    { "rv64um-p-divw.bin", 141 },
    { "rv64um-p-mul.bin", 499 },
    { "rv64um-p-mulh.bin", 507 },
    { "rv64um-p-mulhsu.bin", 507 },
    { "rv64um-p-mulhu.bin", 539 },
    { "rv64um-p-mulw.bin", 438 },
    { "rv64um-p-rem.bin", 139 },
    { "rv64um-p-remu.bin", 140 },
    { "rv64um-p-remuw.bin", 135 },
    { "rv64um-p-remw.bin", 141 },
    { "rv64um-v-div.bin", 7940 },
    { "rv64um-v-divu.bin", 7938 },
    { "rv64um-v-divuw.bin", 7930 },
    { "rv64um-v-divw.bin", 7933 },
    { "rv64um-v-mul.bin", 8291 },
    { "rv64um-v-mulh.bin", 8299 },
    { "rv64um-v-mulhsu.bin", 8299 },
    { "rv64um-v-mulhu.bin", 8331 },
    { "rv64um-v-mulw.bin", 8230 },
    { "rv64um-v-rem.bin", 7931 },
    { "rv64um-v-remu.bin", 7932 },
    { "rv64um-v-remuw.bin", 7927 },
    { "rv64um-v-remw.bin", 7933 },
    { "rv64uzba-p-add_uw.bin", 513 },
    { "rv64uzba-p-sh1add.bin", 516 },
    { "rv64uzba-p-sh1add_uw.bin", 520 },
    { "rv64uzba-p-sh2add.bin", 516 },
    { "rv64uzba-p-sh2add_uw.bin", 520 },
    { "rv64uzba-p-sh3add.bin", 516 },
    { "rv64uzba-p-sh3add_uw.bin", 520 },
    { "rv64uzba-p-slli_uw.bin", 321 },
    { "rv64uzba-v-add_uw.bin", 8243 },
    { "rv64uzba-v-sh1add.bin", 8246 },
    { "rv64uzba-v-sh1add_uw.bin", 8250 },
    { "rv64uzba-v-sh2add.bin", 8246 },
    { "rv64uzba-v-sh2add_uw.bin", 8250 },
    { "rv64uzba-v-sh3add.bin", 8246 },
    { "rv64uzba-v-sh3add_uw.bin", 8250 },
    { "rv64uzba-v-slli_uw.bin", 8051 },
    { "rv64uzbb-p-andn.bin", 593 },
    { "rv64uzbb-p-clz.bin", 270 },
    { "rv64uzbb-p-clzw.bin", 257 },
    { "rv64uzbb-p-cpop.bin", 270 },
    { "rv64uzbb-p-cpopw.bin", 257 },
    { "rv64uzbb-p-ctz.bin", 270 },
    { "rv64uzbb-p-ctzw.bin", 258 },
    { "rv64uzbb-p-max.bin", 503 },
    { "rv64uzbb-p-maxu.bin", 532 },
    { "rv64uzbb-p-min.bin", 499 },
    { "rv64uzbb-p-minu.bin", 521 },
    { "rv64uzbb-p-orc_b.bin", 294 },
    { "rv64uzbb-p-orn.bin", 602 },
    { "rv64uzbb-p-rev8.bin", 312 },
    { "rv64uzbb-p-rol.bin", 584 },
    { "rv64uzbb-p-rolw.bin", 583 },
    { "rv64uzbb-p-ror.bin", 611 },
    { "rv64uzbb-p-rori.bin", 324 },
    { "rv64uzbb-p-roriw.bin", 282 },
    { "rv64uzbb-p-rorw.bin", 543 },
    { "rv64uzbb-p-sext_b.bin", 270 },
    { "rv64uzbb-p-sext_h.bin", 273 },
    { "rv64uzbb-p-xnor.bin", 601 },
    { "rv64uzbb-p-zext_h.bin", 277 },
    { "rv64uzbb-v-andn.bin", 14251 },
    { "rv64uzbb-v-clz.bin", 8063 },
    { "rv64uzbb-v-clzw.bin", 8050 },
    { "rv64uzbb-v-cpop.bin", 8063 },
    { "rv64uzbb-v-cpopw.bin", 8050 },
    { "rv64uzbb-v-ctz.bin", 8063 },
    { "rv64uzbb-v-ctzw.bin", 8051 },
    { "rv64uzbb-v-max.bin", 8296 },
    { "rv64uzbb-v-maxu.bin", 14190 },
    { "rv64uzbb-v-min.bin", 8292 },
    { "rv64uzbb-v-minu.bin", 8314 },
    { "rv64uzbb-v-orc_b.bin", 8087 },
    { "rv64uzbb-v-orn.bin", 14260 },
    { "rv64uzbb-v-rev8.bin", 8105 },
    { "rv64uzbb-v-rol.bin", 14242 },
    { "rv64uzbb-v-rolw.bin", 14241 },
    { "rv64uzbb-v-ror.bin", 14269 },
    { "rv64uzbb-v-rori.bin", 8117 },
    { "rv64uzbb-v-roriw.bin", 8075 },
    { "rv64uzbb-v-rorw.bin", 14201 },
    { "rv64uzbb-v-sext_b.bin", 8063 },
    { "rv64uzbb-v-sext_h.bin", 8066 },
    { "rv64uzbb-v-xnor.bin", 14259 },
    { "rv64uzbb-v-zext_h.bin", 8070 },
    { "rv64uzbc-p-clmul.bin", 500 },
    { "rv64uzbc-p-clmulh.bin", 505 },
    { "rv64uzbc-p-clmulr.bin", 503 },
    { "rv64uzbc-v-clmul.bin", 8292 },
    { "rv64uzbc-v-clmulh.bin", 8297 },
    { "rv64uzbc-v-clmulr.bin", 8295 },
    { "rv64uzbs-p-bclr.bin", 699 },
    { "rv64uzbs-p-bclri.bin", 354 },
    { "rv64uzbs-p-bext.bin", 634 },
    { "rv64uzbs-p-bexti.bin", 324 },
    { "rv64uzbs-p-binv.bin", 598 },
    { "rv64uzbs-p-binvi.bin", 319 },
    { "rv64uzbs-p-bset.bin", 701 },
    { "rv64uzbs-p-bseti.bin", 362 },
    { "rv64uzbs-v-bclr.bin", 14292 },
    { "rv64uzbs-v-bclri.bin", 8083 },
    { "rv64uzbs-v-bext.bin", 14227 },
    { "rv64uzbs-v-bexti.bin", 8053 },
    { "rv64uzbs-v-binv.bin", 14191 },
    { "rv64uzbs-v-binvi.bin", 8048 },
    { "rv64uzbs-v-bset.bin", 14294 },
    { "rv64uzbs-v-bseti.bin", 8091 },

    -- extensions that are built, but unsupported yet
    -- { "rv64mi-p-pmpaddr.bin", 10000 },
    -- { "rv64mzicbo-p-zero.bin", 10000 },
    -- { "rv64ui-p-ma_data.bin", 10000 },
    -- { "rv64ui-v-ma_data.bin", 10000 },
    -- { "rv64uzfh-p-fadd.bin", 10000 },
    -- { "rv64uzfh-p-fclass.bin", 10000 },
    -- { "rv64uzfh-p-fcmp.bin", 10000 },
    -- { "rv64uzfh-p-fcvt.bin", 10000 },
    -- { "rv64uzfh-p-fcvt_w.bin", 10000 },
    -- { "rv64uzfh-p-fdiv.bin", 10000 },
    -- { "rv64uzfh-p-fmadd.bin", 10000 },
    -- { "rv64uzfh-p-fmin.bin", 10000 },
    -- { "rv64uzfh-p-ldst.bin", 10000 },
    -- { "rv64uzfh-p-move.bin", 10000 },
    -- { "rv64uzfh-p-recoding.bin", 10000 },
    -- { "rv64uzfh-v-fadd.bin", 10000 },
    -- { "rv64uzfh-v-fclass.bin", 10000 },
    -- { "rv64uzfh-v-fcmp.bin", 10000 },
    -- { "rv64uzfh-v-fcvt.bin", 10000 },
    -- { "rv64uzfh-v-fcvt_w.bin", 10000 },
    -- { "rv64uzfh-v-fdiv.bin", 10000 },
    -- { "rv64uzfh-v-fmadd.bin", 10000 },
    -- { "rv64uzfh-v-fmin.bin", 10000 },
    -- { "rv64uzfh-v-ldst.bin", 10000 },
    -- { "rv64uzfh-v-move.bin", 10000 },
    -- { "rv64uzfh-v-recoding.bin", 10000 },

    -- cartesi tests
    { "access.bin", 97 },
    { "amo.bin", 166 },
    { "clint_ops.bin", 133 },
    { "compressed.bin", 410 },
    { "csr_counters.bin", 737 },
    { "csr_semantics.bin", 378 },
    { "dont_write_x0.bin", 64 },
    { "ebreak.bin", 17 },
    { "fbinary_d.bin", 204284 },
    { "fbinary_s.bin", 204284 },
    { "fclass.bin", 457 },
    { "fcmp.bin", 46787 },
    { "fcvt.bin", 17614 },
    { "fternary_d.bin", 216784 },
    { "fternary_s.bin", 216784 },
    { "funary.bin", 2834 },
    { "htif_invalid_ops.bin", 109 },
    { "illegal_insn.bin", 972 },
    { "interrupts.bin", 8209 },
    { "lrsc_semantics.bin", 31 },
    { "mcycle_write.bin", 14 },
    { "mtime_interrupt.bin", 16404 },
    { "pte_reserved_exception.bin", 30 },
    { "sd_pma_overflow.bin", 12 },
    { "shadow_ops.bin", 78 },
    { "translate_vaddr.bin", 343 },
    { "version_check.bin", 26 },
    { "xpie_exceptions.bin", 47 },
}

local log_annotations = false

-- Microarchitecture configuration
local uarch

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s [options] <command>

where options are:

  --test-path=<dir>
    path to test binaries
    (default: environment $CARTESI_TESTS_PATH)

  --test=<pattern>
    select tests to run based on a Lua string <pattern>
    (default: ".*", i.e., all tests)

  --jobs=<N>
    run N tests in parallel
    (default: 1, i.e., run tests sequentially)

  --log-annotations
    include annotations in logs

  --periodic-action=<number-period>[,<number-start>]
    stop execution every <number> of uarch cycles and perform action. If
    <number-start> is given, the periodic action will start at that
    uarch cycle. Only take effect with hash and step commands.
    (default: none)

  --remote-address=<ip>:<port>
    use a remote cartesi machine listening to <ip>:<port> instead of
    running a local cartesi machine.

  --output=<filename>
    write the output of hash and step commands to the file at
    <filename>. If the argument is not present the output is written
    to stdout.
    (default: none)

  --json-test-list
    write the output of the list command as json

  --uarch-ram-image=<filename>
    name of file containing microarchitecture RAM image.

and command can be:

  run
    run test and report if payload and cycles match expected

  run_step
    run all tests by recording and verifying each test execution into a step log file

  run_uarch
    run test in the microarchitecture and report if payload and cycles match expected

  run_host_and_uarch
    run test in two machines: host and microarchitecture based; checking if root hashes match after each mcycle.

  hash
    output root hash at every <number> of cycles

  step
    output json log of step at every <number> of cycles

  dump
    dump machine initial state memory ranges on current directory

  list
    list tests selected by the test <pattern>

  machine
    prints a command for running the test machine

<number> can be specified in decimal (e.g., 16) or hexadeximal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

]=],
        arg[0]
    ))
    os.exit()
end

local test_path = test_util.tests_path
local test_pattern = ".*"
local remote_address
local output
local jobs = 1
local json_list = false
local periodic_action = false
local periodic_action_period = math.maxinteger
local periodic_action_start = 0
local concurrency_update_hash_tree = util.parse_number(os.getenv("CARTESI_CONCURRENCY_UPDATE_HASH_TREE")) or 0

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    {
        "^%-%-h$",
        function(all)
            if not all then
                return false
            end
            help()
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then
                return false
            end
            help()
        end,
    },
    {
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            remote_address = o
            return true
        end,
    },
    {
        "^%-%-output%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            output = o
            return true
        end,
    },
    {
        "^%-%-json%-test%-list$",
        function(all)
            if not all then
                return false
            end
            json_list = true
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            test_path = o
            return true
        end,
    },
    {
        "^%-%-test%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            test_pattern = o
            return true
        end,
    },
    {
        "^%-%-jobs%=([0-9]+)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            jobs = assert(tonumber(o))
            assert(jobs and jobs >= 1, "invalid number of jobs")
            return true
        end,
    },
    {
        "^%-%-log%-annotations$",
        function(o)
            if not o then
                return false
            end
            log_annotations = true
            return true
        end,
    },
    {
        "^(%-%-periodic%-action%=(.*))$",
        function(all, v)
            if not v then
                return false
            end
            string.gsub(v, "^([^%,]+),(.+)$", function(p, s)
                periodic_action_period = assert(util.parse_number(p), "invalid period " .. all)
                periodic_action_start = assert(util.parse_number(s), "invalid start " .. all)
            end)
            if periodic_action_period == math.maxinteger then
                periodic_action_period = assert(util.parse_number(v), "invalid period " .. all)
                periodic_action_start = 0
            end
            assert(periodic_action_period > 0, "invalid period " .. periodic_action_period)
            periodic_action = true
            return true
        end,
    },
    {
        "^(%-%-concurrency%=(.+))$",
        function(all, opts)
            if not opts then
                return false
            end
            local c = util.parse_options(opts, all, {
                update_hash_tree = "number",
            })
            c.update_hash_tree = assert(c.update_hash_tree, "invalid update_hash_tree number in " .. all)
            concurrency_update_hash_tree = c.update_hash_tree
            return true
        end,
    },
    {
        "^%-%-uarch%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            uarch = uarch or {}
            uarch.ram = uarch.ram or {}
            uarch.ram.backing_store = uarch.ram.backing_store or {}
            uarch.ram.backing_store.data_filename = o
            return true
        end,
    },
    {
        ".*",
        function(all)
            error("unrecognized option " .. all)
        end,
    },
}

local values = {}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        values[#values + 1] = argument
    end
end

local command = assert(values[1], "missing command")
assert(test_path, "missing test path")

local to_shutdown -- luacheck: no unused
if remote_address then
    jsonrpc = require("cartesi.jsonrpc")
    to_shutdown = jsonrpc.connect_server(remote_address):set_cleanup_call(jsonrpc.SHUTDOWN)
end

local function advance_machine(machine, max_mcycle)
    return machine:run(max_mcycle)
end

local function run_machine(machine, ctx, max_mcycle, advance_machine_fn)
    advance_machine_fn = advance_machine_fn or advance_machine
    local mcycle = machine:read_reg("mcycle")
    while math.ult(mcycle, max_mcycle) do
        advance_machine_fn(machine, max_mcycle)
        mcycle = machine:read_reg("mcycle")
        if machine:read_reg("iflags_H") ~= 0 then
            break
        end
    end
    ctx.read_htif_tohost_data = machine:read_reg("htif_tohost_data")
end

local function advance_machine_with_uarch(machine)
    if machine:run_uarch() == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
        machine:reset_uarch()
    end
end

local function run_machine_with_uarch(machine, ctx, max_mcycle)
    run_machine(machine, ctx, max_mcycle, advance_machine_with_uarch)
end

local function build_machine(ram_image)
    local config = {
        ram = {
            length = 32 << 20,
            backing_store = {
                data_filename = test_path .. "/" .. ram_image,
            },
        },
        flash_drive = { {
            start = 0x80000000000000,
            length = 0x40000,
        } },
    }
    if uarch then
        config.uarch = uarch
    end
    local runtime = {
        concurrency = {
            update_hash_tree = concurrency_update_hash_tree,
        },
    }
    if remote_address then
        local jsonrpc_machine <close> = assert(jsonrpc.connect_server(remote_address))
        return jsonrpc_machine:fork_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(config, runtime)
    end
    return cartesi.machine(config, runtime)
end

local function print_machine(test_name, expected_cycles)
    if not uarch then
        print(string.format(
            "./cartesi-machine.lua \
 --ram-length=32Mi\
 --ram-image='%s'\
 --no-bootargs\
 --max-mcycle=%d ",
            test_path .. "/" .. test_name,
            2 * expected_cycles
        ))
    else
        print(string.format(
            "./cartesi-machine.lua \
 --ram-length=32Mi\
 --ram-image='%s'\
 --no-bootargs\
 --uarch-ram-image=%s\
 --max-mcycle=%d ",
            test_path .. "/" .. test_name,
            uarch.ram.backing_store.data_filename,
            2 * expected_cycles
        ))
    end
end

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end
local function fatal(fmt, ...)
    error(string.format(fmt, ...))
end
local function check_and_print_result(machine, ctx)
    local cycles = machine:read_reg("mcycle")
    if machine:read_reg("iflags_H") ~= 1 then
        fatal("%s: failed. terminated at mcycle = %d without halt\n", ctx.ram_image, cycles)
    end

    local halt_payload = machine:read_reg("htif_tohost_data") >> 1
    local expected_halt_payload = ctx.expected_halt_payload or 0
    if halt_payload ~= expected_halt_payload then
        fatal("%s: failed. returned halt payload %d, expected %d\n", ctx.ram_image, halt_payload, expected_halt_payload)
    end

    -- print(string.format([[{ "%s", %d },]], ctx.ram_image, cycles))

    local expected_cycles = ctx.expected_cycles or 0
    if cycles ~= expected_cycles then
        fatal("%s: failed. terminated with mcycle = %d, expected %d\n", ctx.ram_image, cycles, expected_cycles)
    end

    stderr("%s: passed\n", ctx.ram_image)
end

local function hash(tests)
    local out = io.stdout
    if output then
        out = assert(io.open(output, "w"), "error opening file: " .. output)
    end
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local expected_payload = test[3] or 0
        local machine <close> = build_machine(ram_image)
        local total_cycles = 0
        local max_mcycle = 2 * expected_cycles
        while math.ult(machine:read_reg("mcycle"), max_mcycle) do
            local initial_cycle = machine:read_reg("uarch_cycle")
            local next_action_cycle = math.maxinteger
            if periodic_action then
                next_action_cycle = periodic_action_start
                if next_action_cycle <= total_cycles then
                    next_action_cycle = next_action_cycle
                        + (
                            (((total_cycles - periodic_action_start) // periodic_action_period) + 1)
                            * periodic_action_period
                        )
                end
            end
            local status = machine:run_uarch(initial_cycle + (next_action_cycle - total_cycles))
            local final_cycle = machine:read_reg("uarch_cycle")
            total_cycles = total_cycles + (final_cycle - initial_cycle)
            if not periodic_action or total_cycles == next_action_cycle then
                out:write(
                    machine:read_reg("mcycle"),
                    " ",
                    final_cycle,
                    " ",
                    util.hexhash(machine:get_root_hash()),
                    "\n"
                )
                total_cycles = total_cycles + 1
            end
            if status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                machine:reset_uarch()
                if machine:read_reg("iflags_H") ~= 0 then
                    break
                end
            end
        end
        if
            machine:read_reg("htif_tohost_data") >> 1 ~= expected_payload
            or machine:read_reg("mcycle") ~= expected_cycles
        then
            os.exit(1, true)
        end
        out:write(
            machine:read_reg("mcycle"),
            " ",
            machine:read_reg("uarch_cycle"),
            " ",
            util.hexhash(machine:get_root_hash()),
            "\n"
        )
    end
end

local function print_machines(tests)
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        print_machine(ram_image, expected_cycles)
    end
end

local function step(tests)
    local out = io.stdout
    if output then
        out = assert(io.open(output, "w"), "error opening file: " .. output)
    end
    local indentout = util.indentout
    local log_type = (log_annotations and cartesi.ACCESS_LOG_TYPE_ANNOTATIONS or 0)
    out:write("[\n")
    for i, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local expected_payload = test[3] or 0
        local machine <close> = build_machine(ram_image)
        indentout(out, 1, "{\n")
        indentout(out, 2, '"test": "%s",\n', ram_image)
        if periodic_action then
            indentout(out, 2, '"period": %u,\n', periodic_action_period)
            indentout(out, 2, '"start": %u,\n', periodic_action_start)
        end
        indentout(out, 2, '"steps": [\n')
        local total_logged_steps = 0
        local total_uarch_cycles = 0
        local max_mcycle = 2 * expected_cycles
        while math.ult(machine:read_reg("mcycle"), max_mcycle) do
            local uarch_cycle_increment = 0
            local next_action_uarch_cycle
            if periodic_action then
                next_action_uarch_cycle = periodic_action_start
                if next_action_uarch_cycle <= total_uarch_cycles then
                    next_action_uarch_cycle = next_action_uarch_cycle
                        + (
                            (((total_uarch_cycles - periodic_action_start) // periodic_action_period) + 1)
                            * periodic_action_period
                        )
                end
                uarch_cycle_increment = next_action_uarch_cycle - total_uarch_cycles
            end
            local init_uarch_cycle = machine:read_reg("uarch_cycle")
            machine:run_uarch(machine:read_reg("uarch_cycle") + uarch_cycle_increment)
            local final_uarch_cycle = machine:read_reg("uarch_cycle")
            total_uarch_cycles = total_uarch_cycles + (final_uarch_cycle - init_uarch_cycle)
            if machine:read_reg("uarch_halt_flag") then
                machine:reset_uarch()
                if machine:read_reg("iflags_H") ~= 0 then
                    break
                end
            end
            if not periodic_action or total_uarch_cycles == next_action_uarch_cycle then
                local init_mcycle = machine:read_reg("mcycle")
                init_uarch_cycle = machine:read_reg("uarch_cycle")
                local log = machine:log_step_uarch(log_type)
                local final_mcycle = machine:read_reg("mcycle")
                final_uarch_cycle = machine:read_reg("uarch_cycle")
                if total_logged_steps > 0 then
                    out:write(",\n")
                end
                util.dump_json_log(log, init_mcycle, init_uarch_cycle, final_mcycle, final_uarch_cycle, out, 3)
                total_uarch_cycles = total_uarch_cycles + 1
                total_logged_steps = total_logged_steps + 1
                if machine:read_reg("uarch_halt_flag") then
                    machine:reset_uarch()
                    if machine:read_reg("iflags_H") ~= 0 then
                        break
                    end
                end
            end
        end
        indentout(out, 2, "]\n")
        if tests[i + 1] then
            indentout(out, 1, "},\n")
        else
            indentout(out, 1, "}\n")
        end
        if
            machine:read_reg("htif_tohost_data") >> 1 ~= expected_payload
            or machine:read_reg("mcycle") ~= expected_cycles
        then
            os.exit(1, true)
        end
    end
    out:write("]\n")
end

local function dump(tests)
    local ram_image = tests[1][1]
    local machine <close> = build_machine(ram_image)
    for _, v in machine:get_memory_ranges() do
        local filename = string.format("%016x--%016x.bin", v.start, v.length)
        local file <close> = assert(io.open(filename, "w"))
        assert(file:write(machine:read_memory(v.start, v.length)))
    end
end

local function list(tests)
    if json_list then
        local out = io.stdout
        local indentout = util.indentout
        out:write('{\n  "tests": [\n')
        for i, test in ipairs(tests) do
            if i ~= 1 then
                out:write(",\n")
            end
            indentout(out, 2, "{\n")
            indentout(out, 3, '"file": "' .. test[1] .. '",\n')
            indentout(out, 3, '"mcycle": ' .. test[2] .. "\n")
            indentout(out, 2, "}")
        end
        out:write("\n  ]\n}\n")
    else
        for _, test in ipairs(tests) do
            print(test[1])
        end
    end
end

local function select_test(test_name, patt)
    local i, j = test_name:find(patt)
    if i == 1 and j == #test_name then
        return true
    end
    i, j = test_name:find(patt, 1, true)
    return i == 1 and j == #test_name
end

local selected_tests = {}
for _, test in ipairs(riscv_tests) do
    if select_test(test[1], test_pattern) then
        selected_tests[#selected_tests + 1] = test
    end
end

local function run_host_and_uarch_machines(host_machine, uarch_machine, ctx, max_mcycle)
    local host_cycles = host_machine:read_reg("mcycle")
    local uarch_cycles = uarch_machine:read_reg("mcycle")
    assert(host_cycles == uarch_cycles)
    if host_cycles ~= uarch_cycles then
        fatal("%s: host_cycles ~= uarch_cycles: %d ~= %d", ctx.ram_image, host_cycles, uarch_cycles)
    end
    while math.ult(host_cycles, max_mcycle) do
        local host_hash = host_machine:get_root_hash()
        local uarch_hash = uarch_machine:get_root_hash()
        if host_hash ~= uarch_hash then
            fatal(
                "%s: Hash mismatch at mcycle %d: %s ~= %s",
                ctx.ram_image,
                host_cycles,
                util.hexhash(host_hash),
                util.hexhash(uarch_hash)
            )
        end
        host_machine:run(1 + host_cycles)
        advance_machine_with_uarch(uarch_machine)
        host_cycles = host_machine:read_reg("mcycle")
        uarch_cycles = uarch_machine:read_reg("mcycle")
        if host_cycles ~= uarch_cycles then
            fatal("%s: host_cycles ~= uarch_cycles: %d ~= %d", ctx.ram_image, host_cycles, uarch_cycles)
        end
        local host_iflags_H = host_machine:read_reg("iflags_H") ~= 0
        local uarch_iflags_H = uarch_machine:read_reg("iflags_H") ~= 0
        if host_iflags_H ~= uarch_iflags_H then
            fatal(
                "%s: host_iflags_H ~= uarch_iflags_H: %s ~= %s",
                ctx.ram_image,
                tostring(host_iflags_H),
                tostring(uarch_iflags_H)
            )
        end
        if host_iflags_H then
            break
        end
    end
    local host_htif_tohost_data = host_machine:read_reg("htif_tohost_data")
    local uarch_htif_tohost_data = uarch_machine:read_reg("htif_tohost_data")
    if host_htif_tohost_data ~= uarch_htif_tohost_data then
        fatal(
            "%s: host_htif_tohost_data ~= uarch_htif_tohost_data: %d ~= %d",
            ctx.ram_image,
            host_htif_tohost_data,
            uarch_htif_tohost_data
        )
    end
    ctx.read_htif_tohost_data = host_htif_tohost_data
    return host_cycles
end

local function run_machine_step(machine, reference_machine, ctx, mcycle_count)
    local log_filename = os.tmpname()
    local deleter = {}
    setmetatable(deleter, {
        __gc = function()
            os.remove(log_filename)
        end,
    })
    os.remove(log_filename)
    local root_hash_before = machine:get_root_hash()
    local reference_hash = reference_machine:get_root_hash()
    if root_hash_before ~= reference_hash then
        fatal("%s: failed. Initial hash does not match reference machine\n", ctx.ram_image)
        return
    end
    machine:log_step(mcycle_count, log_filename)
    local root_hash_after = machine:get_root_hash()
    cartesi.machine:verify_step(root_hash_before, log_filename, mcycle_count, root_hash_after)
    -- run the reference machine normally and check final hashes
    reference_machine:run(mcycle_count)
    reference_hash = reference_machine:get_root_hash()
    if root_hash_after ~= reference_hash then
        fatal("%s: failed. Final hash does not match reference machine\n", ctx.ram_image)
    end
    ctx.read_htif_tohost_data = machine:read_reg("htif_tohost_data")
end

local failures = nil
local contexts = tabular.expand({ "ram_image", "expected_cycles", "expected_halt_payload" }, selected_tests)

if #selected_tests < 1 then
    error("no test selected")
elseif command == "run" then
    failures = parallel.run(contexts, jobs, function(row)
        local machine <close> = build_machine(row.ram_image)
        run_machine(machine, row, 2 * row.expected_cycles)
        check_and_print_result(machine, row)
    end)
elseif command == "run_step" then
    failures = parallel.run(contexts, jobs, function(row)
        local machine <close> = build_machine(row.ram_image)
        local reference_machine <close> = build_machine(row.ram_image)
        run_machine_step(machine, reference_machine, row, row.expected_cycles)
        check_and_print_result(machine, row)
    end)
elseif command == "run_uarch" then
    failures = parallel.run(contexts, jobs, function(row)
        local machine <close> = build_machine(row.ram_image)
        run_machine_with_uarch(machine, row, 2 * row.expected_cycles)
        check_and_print_result(machine, row)
    end)
elseif command == "run_host_and_uarch" then
    failures = parallel.run(contexts, jobs, function(row)
        local host_machine <close> = build_machine(row.ram_image)
        local uarch_machine <close> = build_machine(row.ram_image)
        run_host_and_uarch_machines(host_machine, uarch_machine, row, 2 * row.expected_cycles)
    end)
elseif command == "hash" then
    hash(selected_tests)
elseif command == "step" then
    step(selected_tests)
elseif command == "dump" then
    dump(selected_tests)
elseif command == "list" then
    list(selected_tests)
elseif command == "machine" then
    print_machines(selected_tests)
else
    error("command not found")
end

-- print summary
if failures ~= nil then
    if failures > 0 then
        io.write(string.format("\nFAILED %d of %d tests\n\n", failures, #selected_tests))
        os.exit(1, true)
    else
        io.write(string.format("\nPASSED all %d tests\n\n", #selected_tests))
        os.exit(0, true)
    end
end
