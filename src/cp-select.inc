// Formation selection for the copy-and-patch backend (copy-patch-rvvm.md).
//
// One CP_SEL case per TC case label (the same ids the jump table decodes
// to), mapping the executed instruction onto formation primitives. Decode
// goes through the interpreter's own insn helpers, so there is no second
// decoder; fused-decode labels discriminate by funct7 exactly as their
// execute bodies do. Anything not selected here ends the trace
// (cp_form_end), which is the RVVM answer to partial coverage: the head
// installs what it has, and the uncovered pc runs interpreted.
//
// Primitives (defined in interpret-cp.cpp):
//   f.reg3(tab, rd, rs1, rs2)       rd = rs1 op rs2 through a slot-cubed table
//   f.reg2i(tab, rd, rs1, imm)      immediate form: li scratch + reg3
//   f.li(rd, value)                 rd = constant
//   f.load(tab, rd, rs1, imm)       hit-or-bail load, imm pre-added
//   f.store(tab, rs1, rs2, imm)     hit-or-bail store, imm pre-added
//   f.branch(tab, rs1, rs2, taken)  guard with recorded direction
//   f.jump(target)                  direct jump: recording continues there
//   f.end()                         uncompilable: finish the trace
// pc is the guest virtual pc of the instruction being recorded.

#define CP_R3(tab) f.reg3(tab, insn_get_rd(insn), insn_get_rs1(insn), insn_get_rs2(insn))
#define CP_R2I(tab) f.reg2i(tab, insn_get_rd(insn), insn_get_rs1(insn), static_cast<uint64_t>(insn_I_get_imm(insn)))
#define CP_LOAD(tab) f.load(tab, insn_get_rd(insn), insn_get_rs1(insn), static_cast<uint64_t>(insn_I_get_imm(insn)))
#define CP_STORE(tab) f.store(tab, insn_get_rs1(insn), insn_get_rs2(insn), static_cast<uint64_t>(insn_S_get_imm(insn)))
#define CP_BR(tab, comp)                                                                                               \
    f.branch(tab, comp, insn_get_rs1(insn), insn_get_rs2(insn), pc + static_cast<uint64_t>(insn_B_get_imm(insn)), 4)

// Compressed operand shorthands.
#define CP_C_RD (insn_get_rd(insn)) // CR/CI position
#define CP_C_RS2 (insn_get_CR_CSS_rs2(insn))
#define CP_C_RDP (insn_get_CIW_CL_rd_CS_CA_rs2(insn)) // rd', rs2' (x8-x15)
#define CP_C_RS1P (insn_get_CL_CS_CA_CB_rs1(insn))    // rs1' (x8-x15)

switch (label) {
    // Upper immediates and direct jumps: constants known at formation.
    case tc_label::LUI_rdN:
        f.li(insn_get_rd(insn), static_cast<uint64_t>(insn_U_get_imm(insn)));
        break;
    case tc_label::AUIPC_rdN:
        f.li(insn_get_rd(insn), pc + static_cast<uint64_t>(insn_U_get_imm(insn)));
        break;
    case tc_label::JAL_rd0:
        f.jump(pc + static_cast<uint64_t>(insn_J_get_imm(insn)));
        break;
    case tc_label::JAL_rdN:
        f.li(insn_get_rd(insn), pc + 4);
        f.jump(pc + static_cast<uint64_t>(insn_J_get_imm(insn)));
        break;

    // Branches: recorded direction becomes the fallthrough of the guard.
    case tc_label::BEQ:
        CP_BR(cp_beq_table, cp_bne_table);
        break;
    case tc_label::BNE:
        CP_BR(cp_bne_table, cp_beq_table);
        break;
    case tc_label::BLT:
        CP_BR(cp_blt_table, cp_bge_table);
        break;
    case tc_label::BGE:
        CP_BR(cp_bge_table, cp_blt_table);
        break;
    case tc_label::BLTU:
        CP_BR(cp_bltu_table, cp_bgeu_table);
        break;
    case tc_label::BGEU:
        CP_BR(cp_bgeu_table, cp_bltu_table);
        break;

    // Integer immediates.
    case tc_label::ADDI_rdN:
        CP_R2I(cp_add_table);
        break;
    case tc_label::SLTI_rdN:
        CP_R2I(cp_slt_table);
        break;
    case tc_label::SLTIU_rdN:
        CP_R2I(cp_sltu_table);
        break;
    case tc_label::XORI_rdN:
        CP_R2I(cp_xor_table);
        break;
    case tc_label::ORI_rdN:
        CP_R2I(cp_or_table);
        break;
    case tc_label::ANDI_rdN:
        CP_R2I(cp_and_table);
        break;
    case tc_label::SLLI_rdN:
        CP_R2I(cp_sll_table);
        break;
    case tc_label::SRLI_SRAI_rdN:
        CP_R2I((insn >> 30) & 1 ? cp_sra_table : cp_srl_table);
        break;
    case tc_label::ADDIW_rdN:
        CP_R2I(cp_addw_table);
        break;
    case tc_label::SLLIW_rdN:
        CP_R2I(cp_sllw_table);
        break;
    case tc_label::SRLIW_SRAIW_rdN:
        CP_R2I((insn >> 30) & 1 ? cp_sraw_table : cp_srlw_table);
        break;

    // Register-register, fused labels discriminated by funct7 as the
    // execute bodies do (0 base, 1 M extension, 0x20 alternate).
    case tc_label::ADD_MUL_SUB_rdN:
        CP_R3(
            insn_get_funct7(insn) == 1 ? cp_mul_table : (insn_get_funct7(insn) == 0x20 ? cp_sub_table : cp_add_table));
        break;
    case tc_label::SLL_MULH_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_mulh_table : cp_sll_table);
        break;
    case tc_label::SLT_MULHSU_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_mulhsu_table : cp_slt_table);
        break;
    case tc_label::SLTU_MULHU_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_mulhu_table : cp_sltu_table);
        break;
    case tc_label::XOR_DIV_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_div_table : cp_xor_table);
        break;
    case tc_label::SRL_DIVU_SRA_rdN:
        CP_R3(
            insn_get_funct7(insn) == 1 ? cp_divu_table : (insn_get_funct7(insn) == 0x20 ? cp_sra_table : cp_srl_table));
        break;
    case tc_label::OR_REM_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_rem_table : cp_or_table);
        break;
    case tc_label::AND_REMU_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_remu_table : cp_and_table);
        break;
    case tc_label::ADDW_MULW_SUBW_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_mulw_table :
                                           (insn_get_funct7(insn) == 0x20 ? cp_subw_table : cp_addw_table));
        break;
    case tc_label::SLLW_rdN:
        CP_R3(cp_sllw_table);
        break;
    case tc_label::SRLW_DIVUW_SRAW_rdN:
        CP_R3(insn_get_funct7(insn) == 1 ? cp_divuw_table :
                                           (insn_get_funct7(insn) == 0x20 ? cp_sraw_table : cp_srlw_table));
        break;
    case tc_label::DIVW_rdN:
        CP_R3(cp_divw_table);
        break;
    case tc_label::REMW_rdN:
        CP_R3(cp_remw_table);
        break;
    case tc_label::REMUW_rdN:
        CP_R3(cp_remuw_table);
        break;

    // Loads and stores, hit-or-bail.
    case tc_label::LD_rdN:
        CP_LOAD(cp_ld_table);
        break;
    case tc_label::LW_rdN:
        CP_LOAD(cp_lw_table);
        break;
    case tc_label::LWU_rdN:
        CP_LOAD(cp_lwu_table);
        break;
    case tc_label::LH_rdN:
        CP_LOAD(cp_lh_table);
        break;
    case tc_label::LHU_rdN:
        CP_LOAD(cp_lhu_table);
        break;
    case tc_label::LB_rdN:
        CP_LOAD(cp_lb_table);
        break;
    case tc_label::LBU_rdN:
        CP_LOAD(cp_lbu_table);
        break;
    case tc_label::SD:
        CP_STORE(cp_sd_table);
        break;
    case tc_label::SW:
        CP_STORE(cp_sw_table);
        break;
    case tc_label::SH:
        CP_STORE(cp_sh_table);
        break;
    case tc_label::SB:
        CP_STORE(cp_sb_table);
        break;

    // Compressed forms, decoded with the same helpers their cases use.
    case tc_label::C_HINT:
    case tc_label::C_NOP:
        break; // architectural no-ops inside a trace
    case tc_label::C_LUI:
        f.li(CP_C_RD, static_cast<uint64_t>(insn_get_C_LUI_imm(insn)));
        break;
    case tc_label::C_LI:
        f.li(CP_C_RD, static_cast<uint64_t>(insn_get_CI_CB_imm_se(insn)));
        break;
    case tc_label::C_J:
        f.jump(pc + static_cast<uint64_t>(insn_get_C_J_imm(insn)));
        break;
    case tc_label::C_MV:
        f.reg3(cp_add_table, CP_C_RD, 0, CP_C_RS2);
        break;
    case tc_label::C_BEQZ:
        f.branch(cp_beq_table, cp_bne_table, CP_C_RS1P, 0, pc + static_cast<uint64_t>(insn_get_C_BEQZ_BNEZ_imm(insn)),
            2);
        break;
    case tc_label::C_BNEZ:
        f.branch(cp_bne_table, cp_beq_table, CP_C_RS1P, 0, pc + static_cast<uint64_t>(insn_get_C_BEQZ_BNEZ_imm(insn)),
            2);
        break;
    case tc_label::C_ADDI:
        f.reg2i(cp_add_table, CP_C_RD, CP_C_RD, static_cast<uint64_t>(insn_get_CI_CB_imm_se(insn)));
        break;
    case tc_label::C_ADDIW:
        f.reg2i(cp_addw_table, CP_C_RD, CP_C_RD, static_cast<uint64_t>(insn_get_CI_CB_imm_se(insn)));
        break;
    case tc_label::C_ADDI4SPN:
        f.reg2i(cp_add_table, CP_C_RDP, 2, static_cast<uint64_t>(insn_get_CIW_imm(insn)));
        break;
    case tc_label::C_ADDI16SP:
        f.reg2i(cp_add_table, 2, 2, static_cast<uint64_t>(insn_get_C_ADDI16SP_imm(insn)));
        break;
    case tc_label::C_ANDI:
        f.reg2i(cp_and_table, CP_C_RS1P, CP_C_RS1P, static_cast<uint64_t>(insn_get_CI_CB_imm_se(insn)));
        break;
    case tc_label::C_SLLI:
        f.reg2i(cp_sll_table, CP_C_RD, CP_C_RD, static_cast<uint64_t>(insn_get_CI_CB_imm(insn)));
        break;
    case tc_label::C_SRAI:
        f.reg2i(cp_sra_table, CP_C_RS1P, CP_C_RS1P, static_cast<uint64_t>(insn_get_CI_CB_imm(insn)));
        break;
    case tc_label::C_SRLI:
        f.reg2i(cp_srl_table, CP_C_RS1P, CP_C_RS1P, static_cast<uint64_t>(insn_get_CI_CB_imm(insn)));
        break;
    case tc_label::C_ADD:
        f.reg3(cp_add_table, CP_C_RD, CP_C_RD, CP_C_RS2);
        break;
    case tc_label::C_SUB:
        f.reg3(cp_sub_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_XOR:
        f.reg3(cp_xor_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_OR:
        f.reg3(cp_or_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_AND:
        f.reg3(cp_and_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_ADDW:
        f.reg3(cp_addw_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_SUBW:
        f.reg3(cp_subw_table, CP_C_RS1P, CP_C_RS1P, CP_C_RDP);
        break;
    case tc_label::C_LD:
        f.load(cp_ld_table, CP_C_RDP, CP_C_RS1P, static_cast<uint64_t>(insn_get_CL_CS_imm(insn)));
        break;
    case tc_label::C_LW:
        f.load(cp_lw_table, CP_C_RDP, CP_C_RS1P, static_cast<uint64_t>(insn_get_C_LW_C_SW_imm(insn)));
        break;
    case tc_label::C_LDSP:
        f.load(cp_ld_table, CP_C_RD, 2, static_cast<uint64_t>(insn_get_C_FLDSP_LDSP_imm(insn)));
        break;
    case tc_label::C_LWSP:
        f.load(cp_lw_table, CP_C_RD, 2, static_cast<uint64_t>(insn_get_C_LWSP_imm(insn)));
        break;
    case tc_label::C_SD:
        f.store(cp_sd_table, CP_C_RS1P, CP_C_RDP, static_cast<uint64_t>(insn_get_CL_CS_imm(insn)));
        break;
    case tc_label::C_SW:
        f.store(cp_sw_table, CP_C_RS1P, CP_C_RDP, static_cast<uint64_t>(insn_get_C_LW_C_SW_imm(insn)));
        break;
    case tc_label::C_SDSP:
        f.store(cp_sd_table, 2, CP_C_RS2, static_cast<uint64_t>(insn_get_C_FSDSP_SDSP_imm(insn)));
        break;
    case tc_label::C_SWSP:
        f.store(cp_sw_table, 2, CP_C_RS2, static_cast<uint64_t>(insn_get_C_SWSP_imm(insn)));
        break;

    // CSR accesses to the FP CSRs, the measured fragment breakers in
    // soft-float and libm code. Other CSRs end the trace.
    case tc_label::CSRRW:
    case tc_label::CSRRS:
    case tc_label::CSRRC: {
        const cp_stencil_t *const(*tab)[CP_NSLOTS] = nullptr;
        const cp_stencil_t *const *rtab = nullptr;
        const bool is_s = label == tc_label::CSRRS;
        const bool is_c = label == tc_label::CSRRC;
        switch (insn >> 20) {
            case 0x001:
                tab = is_s ? cp_csrrs_fflags_table : (is_c ? cp_csrrc_fflags_table : cp_csrrw_fflags_table);
                rtab = is_s || is_c ? cp_csrr_fflags_table : nullptr;
                break;
            case 0x002:
                tab = is_s ? cp_csrrs_frm_table : (is_c ? cp_csrrc_frm_table : cp_csrrw_frm_table);
                rtab = is_s || is_c ? cp_csrr_frm_table : nullptr;
                break;
            case 0x003:
                tab = is_s ? cp_csrrs_fcsr_table : (is_c ? cp_csrrc_fcsr_table : cp_csrrw_fcsr_table);
                rtab = is_s || is_c ? cp_csrr_fcsr_table : nullptr;
                break;
            default:
                break;
        }
        if (tab == nullptr) {
            f.end();
            break;
        }
        f.csr(tab, rtab, insn_get_rd(insn), insn_get_rs1(insn));
        break;
    }

    // Binary FP arithmetic: the RNE/DYN hard attempt stays in generated
    // code; every hard guard miss runs the same instruction body in
    // soft_only mode and rejoins after the result store. Other rounding
    // modes remain trace boundaries until their always-soft call shape is
    // measured.
    case tc_label::FD: {
        if (!cp_fp_enabled()) {
            f.end();
            break;
        }
        const uint32_t rm = (insn >> 12) & 7;
        const bool dynamic_rm = rm == FRM_DYN;
        const auto funct7 = static_cast<insn_FD_funct7>(insn_get_funct7(insn));
        const bool guarded_arithmetic = funct7 == insn_FD_funct7::FADD_S || funct7 == insn_FD_funct7::FADD_D ||
            funct7 == insn_FD_funct7::FSUB_S || funct7 == insn_FD_funct7::FSUB_D || funct7 == insn_FD_funct7::FMUL_S ||
            funct7 == insn_FD_funct7::FMUL_D || funct7 == insn_FD_funct7::FDIV_S || funct7 == insn_FD_funct7::FDIV_D;
        if (guarded_arithmetic && rm != FRM_RNE && !dynamic_rm) {
            f.fp_soft(insn);
            break;
        }
        switch (funct7) {
            case insn_FD_funct7::FADD_S:
                f.fp_binary(dynamic_rm ? cp_fp_add_s_dyn_table : cp_fp_add_s_rne_table, insn);
                break;
            case insn_FD_funct7::FADD_D:
                f.fp_binary(dynamic_rm ? cp_fp_add_d_dyn_table : cp_fp_add_d_rne_table, insn);
                break;
            case insn_FD_funct7::FSUB_S:
                f.fp_binary(dynamic_rm ? cp_fp_sub_s_dyn_table : cp_fp_sub_s_rne_table, insn);
                break;
            case insn_FD_funct7::FSUB_D:
                f.fp_binary(dynamic_rm ? cp_fp_sub_d_dyn_table : cp_fp_sub_d_rne_table, insn);
                break;
            case insn_FD_funct7::FMUL_S:
                f.fp_binary(dynamic_rm ? cp_fp_mul_s_dyn_table : cp_fp_mul_s_rne_table, insn);
                break;
            case insn_FD_funct7::FMUL_D:
                f.fp_binary(dynamic_rm ? cp_fp_mul_d_dyn_table : cp_fp_mul_d_rne_table, insn);
                break;
            case insn_FD_funct7::FDIV_S:
                f.fp_binary(dynamic_rm ? cp_fp_div_s_dyn_table : cp_fp_div_s_rne_table, insn);
                break;
            case insn_FD_funct7::FDIV_D:
                f.fp_binary(dynamic_rm ? cp_fp_div_d_dyn_table : cp_fp_div_d_rne_table, insn);
                break;
            case insn_FD_funct7::FSQRT_S:
                if (rm == FRM_RNE || dynamic_rm) {
                    f.fp_unary(dynamic_rm ? cp_fp_sqrt_s_dyn_table : cp_fp_sqrt_s_rne_table, insn);
                } else {
                    f.fp_soft(insn);
                }
                break;
            case insn_FD_funct7::FSQRT_D:
                if (rm == FRM_RNE || dynamic_rm) {
                    f.fp_unary(dynamic_rm ? cp_fp_sqrt_d_dyn_table : cp_fp_sqrt_d_rne_table, insn);
                } else {
                    f.fp_soft(insn);
                }
                break;
            case insn_FD_funct7::FSGN_S:
                switch (static_cast<insn_FSGN_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
                    case insn_FSGN_funct3_000000000000::J:
                        f.fp_exact_binary(cp_fp_fsgnj_s_table, insn);
                        break;
                    case insn_FSGN_funct3_000000000000::JN:
                        f.fp_exact_binary(cp_fp_fsgnjn_s_table, insn);
                        break;
                    case insn_FSGN_funct3_000000000000::JX:
                        f.fp_exact_binary(cp_fp_fsgnjx_s_table, insn);
                        break;
                    default:
                        f.end();
                        break;
                }
                break;
            case insn_FD_funct7::FSGN_D:
                switch (static_cast<insn_FSGN_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
                    case insn_FSGN_funct3_000000000000::J:
                        f.fp_exact_binary(cp_fp_fsgnj_d_table, insn);
                        break;
                    case insn_FSGN_funct3_000000000000::JN:
                        f.fp_exact_binary(cp_fp_fsgnjn_d_table, insn);
                        break;
                    case insn_FSGN_funct3_000000000000::JX:
                        f.fp_exact_binary(cp_fp_fsgnjx_d_table, insn);
                        break;
                    default:
                        f.end();
                        break;
                }
                break;
            case insn_FD_funct7::FMINMAX_S:
                if (insn_get_funct3_000000000000(insn) == insn_FMIN_FMAX_funct3_000000000000::MIN) {
                    f.fp_exact_binary(cp_fp_min_s_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FMIN_FMAX_funct3_000000000000::MAX) {
                    f.fp_exact_binary(cp_fp_max_s_table, insn);
                } else {
                    f.end();
                }
                break;
            case insn_FD_funct7::FMINMAX_D:
                if (insn_get_funct3_000000000000(insn) == insn_FMIN_FMAX_funct3_000000000000::MIN) {
                    f.fp_exact_binary(cp_fp_min_d_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FMIN_FMAX_funct3_000000000000::MAX) {
                    f.fp_exact_binary(cp_fp_max_d_table, insn);
                } else {
                    f.end();
                }
                break;
            case insn_FD_funct7::FCMP_S:
                if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::EQ) {
                    f.fp_exact_cmp(cp_fp_eq_s_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::LE) {
                    f.fp_exact_cmp(cp_fp_le_s_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::LT) {
                    f.fp_exact_cmp(cp_fp_lt_s_table, insn);
                } else {
                    f.end();
                }
                break;
            case insn_FD_funct7::FCMP_D:
                if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::EQ) {
                    f.fp_exact_cmp(cp_fp_eq_d_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::LE) {
                    f.fp_exact_cmp(cp_fp_le_d_table, insn);
                } else if (insn_get_funct3_000000000000(insn) == insn_FCMP_funct3_000000000000::LT) {
                    f.fp_exact_cmp(cp_fp_lt_d_table, insn);
                } else {
                    f.end();
                }
                break;
            default:
                const auto funct7_rs2 = static_cast<insn_FD_funct7_rs2>(insn_get_funct7_rs2(insn));
                const auto funct3 =
                    static_cast<insn_FMV_FCLASS_funct3_000000000000>(insn_get_funct3_000000000000(insn));
                if (funct3 == insn_FMV_FCLASS_funct3_000000000000::FCLASS &&
                    funct7_rs2 == insn_FD_funct7_rs2::FMV_FCLASS_S) {
                    f.fp_exact_unary_x(cp_fp_class_s_table, insn);
                } else if (funct3 == insn_FMV_FCLASS_funct3_000000000000::FCLASS &&
                    funct7_rs2 == insn_FD_funct7_rs2::FMV_FCLASS_D) {
                    f.fp_exact_unary_x(cp_fp_class_d_table, insn);
                } else {
                    f.end();
                }
                break;
        }
        break;
    }

    case tc_label::FMADD:
    case tc_label::FMSUB:
    case tc_label::FNMADD:
    case tc_label::FNMSUB: {
        if (!cp_fp_enabled()) {
            f.end();
            break;
        }
        const uint32_t rm = (insn >> 12) & 7;
        const bool dynamic_rm = rm == FRM_DYN;
        if (rm != FRM_RNE && !dynamic_rm) {
            f.fp_soft(insn);
            break;
        }
        const bool is_double =
            insn_get_funct2_0000000000000000000000000(insn) == insn_FM_funct2_0000000000000000000000000::D;
#define CP_FP_FMA_TABLE(name)                                                                                          \
    (is_double ? (dynamic_rm ? cp_fp_##name##_d_dyn_table : cp_fp_##name##_d_rne_table) :                              \
                 (dynamic_rm ? cp_fp_##name##_s_dyn_table : cp_fp_##name##_s_rne_table))
        switch (label) {
            case tc_label::FMADD:
                f.fp_ternary(CP_FP_FMA_TABLE(fmadd), insn);
                break;
            case tc_label::FMSUB:
                f.fp_ternary(CP_FP_FMA_TABLE(fmsub), insn);
                break;
            case tc_label::FNMADD:
                f.fp_ternary(CP_FP_FMA_TABLE(fnmadd), insn);
                break;
            case tc_label::FNMSUB:
                f.fp_ternary(CP_FP_FMA_TABLE(fnmsub), insn);
                break;
            default:
                __builtin_unreachable();
        }
#undef CP_FP_FMA_TABLE
        break;
    }

    // Indirect jumps end the trace through the dynamic terminal (deposit
    // plus front-cache lookup); target semantics are the interpreter's:
    // (x[rs1] + imm) & ~1, link written after the target read.
    case tc_label::JALR_rd0:
        f.jalr(0, insn_get_rs1(insn), static_cast<uint64_t>(insn_I_get_imm(insn)), 4);
        break;
    case tc_label::JALR_rdN:
        f.jalr(insn_get_rd(insn), insn_get_rs1(insn), static_cast<uint64_t>(insn_I_get_imm(insn)), 4);
        break;
    case tc_label::C_JR:
        f.jalr(0, CP_C_RD, 0, 2);
        break;
    case tc_label::C_JALR:
        f.jalr(1, CP_C_RD, 0, 2);
        break;

    // Architectural no-ops: rd=x0 arithmetic (including the canonical nop,
    // addi x0,x0,0, used as alignment padding inside hot code). No side
    // effects and no traps, so nothing is emitted; the instruction only
    // retires, which the recording accounts for. Ending the trace here
    // instead was measured shattering the regs shuffle stretches and
    // poisoning their heads with interpreted markers.
    case tc_label::LUI_rd0:
    case tc_label::AUIPC_rd0:
    case tc_label::ADDI_rd0:
    case tc_label::SLTI_rd0:
    case tc_label::SLTIU_rd0:
    case tc_label::XORI_rd0:
    case tc_label::ORI_rd0:
    case tc_label::ANDI_rd0:
    case tc_label::SLLI_rd0:
    case tc_label::SRLI_SRAI_rd0:
    case tc_label::ADD_MUL_SUB_rd0:
    case tc_label::XOR_DIV_rd0:
    case tc_label::SRL_DIVU_SRA_rd0:
    case tc_label::OR_REM_rd0:
    case tc_label::AND_REMU_rd0:
    case tc_label::ADDIW_rd0:
    case tc_label::SLLIW_rd0:
    case tc_label::SRLIW_SRAIW_rd0:
    case tc_label::DIVW_rd0:
    case tc_label::REMW_rd0:
    case tc_label::REMUW_rd0:
        break;

    // Everything else (system, other CSR, atomics, remaining FP) ends the trace.
    default:
        f.end();
        break;
}

#undef CP_R3
#undef CP_R2I
#undef CP_LOAD
#undef CP_STORE
#undef CP_BR
#undef CP_C_RD
#undef CP_C_RS2
#undef CP_C_RDP
#undef CP_C_RS1P
