// Copyright 2020 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include "grpc-util.h"

namespace cartesi {

semantic_version get_proto_semantic_version(
    const Versioning::SemanticVersion &proto_v) {
    semantic_version v;
    v.major = proto_v.major();
    v.minor = proto_v.minor();
    v.patch = proto_v.patch();
    v.pre_release = proto_v.pre_release();
    v.build = proto_v.build();
    return v;
}

void set_proto_machine_config(const machine_config &c,
    CartesiMachine::MachineConfig* proto_c) {
    auto *proto_rom = proto_c->mutable_rom();
    proto_rom->set_bootargs(c.rom.bootargs);
    proto_rom->set_image_filename(c.rom.image_filename);
    auto *proto_ram = proto_c->mutable_ram();
    proto_ram->set_length(c.ram.length);
    proto_ram->set_image_filename(c.ram.image_filename);
    auto *proto_htif = proto_c->mutable_htif();
    proto_htif->set_console_getchar(c.htif.console_getchar);
    proto_htif->set_yield_progress(c.htif.yield_progress);
    proto_htif->set_yield_rollup(c.htif.yield_rollup);
    proto_htif->set_fromhost(c.htif.fromhost);
    proto_htif->set_tohost(c.htif.tohost);
    auto *proto_clint = proto_c->mutable_clint();
    proto_clint->set_mtimecmp(c.clint.mtimecmp);
    auto *proto_p = proto_c->mutable_processor();
    proto_p->set_x1(c.processor.x[1]);
    proto_p->set_x2(c.processor.x[2]);
    proto_p->set_x3(c.processor.x[3]);
    proto_p->set_x4(c.processor.x[4]);
    proto_p->set_x5(c.processor.x[5]);
    proto_p->set_x6(c.processor.x[6]);
    proto_p->set_x7(c.processor.x[7]);
    proto_p->set_x8(c.processor.x[8]);
    proto_p->set_x9(c.processor.x[9]);
    proto_p->set_x10(c.processor.x[10]);
    proto_p->set_x11(c.processor.x[11]);
    proto_p->set_x12(c.processor.x[12]);
    proto_p->set_x13(c.processor.x[13]);
    proto_p->set_x14(c.processor.x[14]);
    proto_p->set_x15(c.processor.x[15]);
    proto_p->set_x16(c.processor.x[16]);
    proto_p->set_x17(c.processor.x[17]);
    proto_p->set_x18(c.processor.x[18]);
    proto_p->set_x19(c.processor.x[19]);
    proto_p->set_x20(c.processor.x[20]);
    proto_p->set_x21(c.processor.x[21]);
    proto_p->set_x22(c.processor.x[22]);
    proto_p->set_x23(c.processor.x[23]);
    proto_p->set_x24(c.processor.x[24]);
    proto_p->set_x25(c.processor.x[25]);
    proto_p->set_x26(c.processor.x[26]);
    proto_p->set_x27(c.processor.x[27]);
    proto_p->set_x28(c.processor.x[28]);
    proto_p->set_x29(c.processor.x[29]);
    proto_p->set_x30(c.processor.x[30]);
    proto_p->set_x31(c.processor.x[31]);
    proto_p->set_pc(c.processor.pc);
    proto_p->set_mvendorid(c.processor.mvendorid);
    proto_p->set_marchid(c.processor.marchid);
    proto_p->set_mimpid(c.processor.mimpid);
    proto_p->set_mcycle(c.processor.mcycle);
    proto_p->set_minstret(c.processor.minstret);
    proto_p->set_mstatus(c.processor.mstatus);
    proto_p->set_mtvec(c.processor.mtvec);
    proto_p->set_mscratch(c.processor.mscratch);
    proto_p->set_mepc(c.processor.mepc);
    proto_p->set_mcause(c.processor.mcause);
    proto_p->set_mtval(c.processor.mtval);
    proto_p->set_misa(c.processor.misa);
    proto_p->set_mie(c.processor.mie);
    proto_p->set_mip(c.processor.mip);
    proto_p->set_medeleg(c.processor.medeleg);
    proto_p->set_mideleg(c.processor.mideleg);
    proto_p->set_mcounteren(c.processor.mcounteren);
    proto_p->set_stvec(c.processor.stvec);
    proto_p->set_sscratch(c.processor.sscratch);
    proto_p->set_sepc(c.processor.sepc);
    proto_p->set_scause(c.processor.scause);
    proto_p->set_stval(c.processor.stval);
    proto_p->set_satp(c.processor.satp);
    proto_p->set_scounteren(c.processor.scounteren);
    proto_p->set_ilrsc(c.processor.ilrsc);
    proto_p->set_iflags(c.processor.iflags);
    for(const auto &f: c.flash_drive) {
        auto *proto_f = proto_c->add_flash_drive();
        proto_f->set_start(f.start);
        proto_f->set_length(f.length);
        proto_f->set_shared(f.shared);
        proto_f->set_image_filename(f.image_filename);
    }
    auto *proto_dhd = proto_c->mutable_dhd();
    proto_dhd->set_tstart(c.dhd.tstart);
    proto_dhd->set_tlength(c.dhd.tlength);
    proto_dhd->set_image_filename(c.dhd.image_filename);
    proto_dhd->set_dlength(c.dhd.dlength);
    proto_dhd->set_hlength(c.dhd.hlength);
    for (int i = 0; i < DHD_H_REG_COUNT; i++) {
        proto_dhd->add_h(c.dhd.h[i]);
    }
}

void set_proto_machine_runtime_config(const machine_runtime_config &r,
    CartesiMachine::MachineRuntimeConfig* proto_r) {
    auto *proto_dhd = proto_r->mutable_dhd();
    proto_dhd->set_source_address(r.dhd.source_address);
    auto *proto_concurrency = proto_r->mutable_concurrency();
    proto_concurrency->set_update_merkle_tree(r.concurrency.update_merkle_tree);
}

access_log::type get_proto_log_type(
    const CartesiMachine::AccessLogType &proto_lt) {
    return access_log::type{
        proto_lt.proofs(),
        proto_lt.annotations()
    };
}

void set_proto_hash(const machine_merkle_tree::hash_type &h,
    CartesiMachine::Hash *proto_h) {
    proto_h->set_data(h.data(), h.size());
}

machine_merkle_tree::hash_type get_proto_hash(const CartesiMachine::Hash &proto_hash) {
    machine_merkle_tree::hash_type hash;
    if (proto_hash.data().size() != hash.size()) {
        throw std::invalid_argument("invalid hash size");
    }
    memcpy(hash.data(), proto_hash.data().data(), proto_hash.data().size());
    return hash;
}

machine_merkle_tree::proof_type get_proto_proof(
    const CartesiMachine::MerkleTreeProof &proto_proof) {
    int log2_target_size = static_cast<int>(proto_proof.log2_target_size());
    int log2_root_size = static_cast<int>(proto_proof.log2_root_size());
    machine_merkle_tree::proof_type p{log2_root_size, log2_target_size};
    p.set_target_address(proto_proof.target_address());
    p.set_target_hash(get_proto_hash(proto_proof.target_hash()));
    p.set_root_hash(get_proto_hash(proto_proof.root_hash()));
    const auto &proto_sibs = proto_proof.sibling_hashes();
    if (log2_root_size - proto_sibs.size() != log2_target_size) {
        throw std::invalid_argument("wrong number of sibling hashes");
    }
    for (int i = 0; i < proto_sibs.size(); i++) {
        p.set_sibling_hash(get_proto_hash(proto_sibs[i]), log2_root_size-1-i);
    }
    return p;
}

void set_proto_proof(const machine_merkle_tree::proof_type &p,
    CartesiMachine::MerkleTreeProof *proto_p) {
    proto_p->set_target_address(p.get_target_address());
    proto_p->set_log2_target_size(p.get_log2_target_size());
    proto_p->set_log2_root_size(p.get_log2_root_size());
    set_proto_hash(p.get_target_hash(), proto_p->mutable_target_hash());
    set_proto_hash(p.get_root_hash(), proto_p->mutable_root_hash());
    for (int log2_size = p.get_log2_root_size()-1;
        log2_size >= p.get_log2_target_size(); --log2_size) {
        set_proto_hash(p.get_sibling_hash(log2_size), proto_p->add_sibling_hashes());
    }
}


void set_proto_access_log(const access_log &al,
    CartesiMachine::AccessLog *proto_al) {
    proto_al->mutable_log_type()->set_annotations(
        al.get_log_type().has_annotations());
    proto_al->mutable_log_type()->set_proofs(al.get_log_type().has_proofs());
    for (const auto &a: al.get_accesses()) {
        auto *proto_a = proto_al->add_accesses();
        switch (a.get_type()) {
            case access_type::read:
                proto_a->set_type(CartesiMachine::AccessType::READ);
                break;
            case access_type::write:
                proto_a->set_type(CartesiMachine::AccessType::WRITE);
                break;
            default:
                throw std::invalid_argument{"invalid AccessType"};
                break;
        }
        proto_a->set_log2_size(a.get_log2_size());
        proto_a->set_address(a.get_address());
        proto_a->set_read(a.get_read().data(), a.get_read().size());
        proto_a->set_written(a.get_written().data(), a.get_written().size());
        if (al.get_log_type().has_proofs() && a.get_proof().has_value()) {
            set_proto_proof(a.get_proof().value(), proto_a->mutable_proof());
        }
    }
    if (al.get_log_type().has_annotations()) {
        for (const auto &bn: al.get_brackets()) {
            auto *proto_bn = proto_al->add_brackets();
            switch (bn.type) {
                case bracket_type::begin:
                    proto_bn->set_type(
                        CartesiMachine::BracketNote_BracketNoteType_BEGIN);
                    break;
                case bracket_type::end:
                    proto_bn->set_type(
                        CartesiMachine::BracketNote_BracketNoteType_END);
                    break;
                default:
                    throw std::invalid_argument{"invalid BracketNoteType"};
                    break;
            }
            proto_bn->set_where(bn.where);
            proto_bn->set_text(bn.text);
        }
        for (const auto &n: al.get_notes()) {
            proto_al->add_notes()->assign(n);
        }
    }
}

bracket_type get_proto_bracket_type(
    CartesiMachine::BracketNote_BracketNoteType proto_b) {
    switch(proto_b) {
        case (CartesiMachine::BracketNote_BracketNoteType_BEGIN):
            return bracket_type::begin;
        case (CartesiMachine::BracketNote_BracketNoteType_END):
            return bracket_type::end;
        default:
            throw std::invalid_argument("invalid BracketType");
    }
}

access_type get_proto_access_type(CartesiMachine::AccessType proto_at) {
    switch (proto_at) {
        case (CartesiMachine::AccessType::READ):
            return access_type::read;
        case (CartesiMachine::AccessType::WRITE):
            return access_type::write;
        default:
            throw std::invalid_argument{"invalid AccessType"};
    };
}

access_log get_proto_access_log(const CartesiMachine::AccessLog &proto_al) {
    if (proto_al.log_type().annotations() &&
        proto_al.accesses().size() != proto_al.notes().size()) {
        throw std::invalid_argument("size of log accesses and notes differ");
    }

    bool has_annotations = proto_al.log_type().annotations();
    bool has_proofs =  proto_al.log_type().proofs();
    auto al = access_log(access_log::type{has_proofs, has_annotations});

    const auto& proto_accesses = proto_al.accesses();
    const auto& proto_brackets = proto_al.brackets();
    const auto& proto_notes = proto_al.notes();
    auto pbr = proto_brackets.begin();
    auto pnt = proto_notes.begin();
    auto pac = proto_accesses.begin();
    uint64_t iac = 0; // curent access index
    while (pac != proto_accesses.end() && pbr != proto_brackets.end()) {
        while (pbr != proto_brackets.end() && pbr->where() == iac) {
            // bracket note points to current access
            al.push_bracket(get_proto_bracket_type(pbr->type()),
                pbr->text().c_str());
            assert(pbr->where() == al.get_brackets().back().where);
            pbr++;
        }
        if (pac != proto_accesses.end()) {
            access a;
            a.set_type(get_proto_access_type(pac->type()));
            a.set_address(pac->address());
            a.set_log2_size(pac->log2_size());
            a.get_read().insert(a.get_read().end(),
                pac->read().begin(), pac->read().end());
            a.get_written().insert(a.get_written().end(),
                pac->written().begin(), pac->written().end());
            std::string note;
            if (has_annotations) {
                note = *pnt++;
            }
            if (has_proofs) {
                a.set_proof(get_proto_proof(pac->proof()));
            }
            al.push_access(a, note.c_str());
            pac++;
            iac++;
        }
    }
    return al;
}

processor_config get_proto_processor_config(
    const CartesiMachine::ProcessorConfig &proto_p) {
    using CartesiMachine::ProcessorConfig;
    processor_config p;
    if (proto_p.x1_oneof_case() == ProcessorConfig::kX1) {
        p.x[1] = proto_p.x1();
    }
    if (proto_p.x2_oneof_case() == ProcessorConfig::kX2) {
        p.x[2] = proto_p.x2();
    }
    if (proto_p.x3_oneof_case() == ProcessorConfig::kX3) {
        p.x[3] = proto_p.x3();
    }
    if (proto_p.x4_oneof_case() == ProcessorConfig::kX4) {
        p.x[4] = proto_p.x4();
    }
    if (proto_p.x5_oneof_case() == ProcessorConfig::kX5) {
        p.x[5] = proto_p.x5();
    }
    if (proto_p.x6_oneof_case() == ProcessorConfig::kX6) {
        p.x[6] = proto_p.x6();
    }
    if (proto_p.x7_oneof_case() == ProcessorConfig::kX7) {
        p.x[7] = proto_p.x7();
    }
    if (proto_p.x8_oneof_case() == ProcessorConfig::kX8) {
        p.x[8] = proto_p.x8();
    }
    if (proto_p.x9_oneof_case() == ProcessorConfig::kX9) {
        p.x[9] = proto_p.x9();
    }
    if (proto_p.x10_oneof_case() == ProcessorConfig::kX10) {
        p.x[10] = proto_p.x10();
    }
    if (proto_p.x11_oneof_case() == ProcessorConfig::kX11) {
        p.x[11] = proto_p.x11();
    }
    if (proto_p.x12_oneof_case() == ProcessorConfig::kX12) {
        p.x[12] = proto_p.x12();
    }
    if (proto_p.x13_oneof_case() == ProcessorConfig::kX13) {
        p.x[13] = proto_p.x13();
    }
    if (proto_p.x14_oneof_case() == ProcessorConfig::kX14) {
        p.x[14] = proto_p.x14();
    }
    if (proto_p.x15_oneof_case() == ProcessorConfig::kX15) {
        p.x[15] = proto_p.x15();
    }
    if (proto_p.x16_oneof_case() == ProcessorConfig::kX16) {
        p.x[16] = proto_p.x16();
    }
    if (proto_p.x17_oneof_case() == ProcessorConfig::kX17) {
        p.x[17] = proto_p.x17();
    }
    if (proto_p.x18_oneof_case() == ProcessorConfig::kX18) {
        p.x[18] = proto_p.x18();
    }
    if (proto_p.x19_oneof_case() == ProcessorConfig::kX19) {
        p.x[19] = proto_p.x19();
    }
    if (proto_p.x20_oneof_case() == ProcessorConfig::kX20) {
        p.x[20] = proto_p.x20();
    }
    if (proto_p.x21_oneof_case() == ProcessorConfig::kX21) {
        p.x[21] = proto_p.x21();
    }
    if (proto_p.x22_oneof_case() == ProcessorConfig::kX22) {
        p.x[22] = proto_p.x22();
    }
    if (proto_p.x23_oneof_case() == ProcessorConfig::kX23) {
        p.x[23] = proto_p.x23();
    }
    if (proto_p.x24_oneof_case() == ProcessorConfig::kX24) {
        p.x[24] = proto_p.x24();
    }
    if (proto_p.x25_oneof_case() == ProcessorConfig::kX25) {
        p.x[25] = proto_p.x25();
    }
    if (proto_p.x26_oneof_case() == ProcessorConfig::kX26) {
        p.x[26] = proto_p.x26();
    }
    if (proto_p.x27_oneof_case() == ProcessorConfig::kX27) {
        p.x[27] = proto_p.x27();
    }
    if (proto_p.x28_oneof_case() == ProcessorConfig::kX28) {
        p.x[28] = proto_p.x28();
    }
    if (proto_p.x29_oneof_case() == ProcessorConfig::kX29) {
        p.x[29] = proto_p.x29();
    }
    if (proto_p.x30_oneof_case() == ProcessorConfig::kX30) {
        p.x[30] = proto_p.x30();
    }
    if (proto_p.x31_oneof_case() == ProcessorConfig::kX31) {
        p.x[31] = proto_p.x31();
    }
    if (proto_p.pc_oneof_case() == ProcessorConfig::kPc) {
        p.pc = proto_p.pc();
    }
    if (proto_p.mvendorid_oneof_case() == ProcessorConfig::kMvendorid) {
        p.mvendorid = proto_p.mvendorid();
    }
    if (proto_p.marchid_oneof_case() == ProcessorConfig::kMarchid) {
        p.marchid = proto_p.marchid();
    }
    if (proto_p.mimpid_oneof_case() == ProcessorConfig::kMimpid) {
        p.mimpid = proto_p.mimpid();
    }
    if (proto_p.mcycle_oneof_case() == ProcessorConfig::kMcycle) {
        p.mcycle = proto_p.mcycle();
    }
    if (proto_p.minstret_oneof_case() == ProcessorConfig::kMinstret) {
        p.minstret = proto_p.minstret();
    }
    if (proto_p.mstatus_oneof_case() == ProcessorConfig::kMstatus) {
        p.mstatus = proto_p.mstatus();
    }
    if (proto_p.mtvec_oneof_case() == ProcessorConfig::kMtvec) {
        p.mtvec = proto_p.mtvec();
    }
    if (proto_p.mscratch_oneof_case() == ProcessorConfig::kMscratch) {
        p.mscratch = proto_p.mscratch();
    }
    if (proto_p.mepc_oneof_case() == ProcessorConfig::kMepc) {
        p.mepc = proto_p.mepc();
    }
    if (proto_p.mcause_oneof_case() == ProcessorConfig::kMcause) {
        p.mcause = proto_p.mcause();
    }
    if (proto_p.mtval_oneof_case() == ProcessorConfig::kMtval) {
        p.mtval = proto_p.mtval();
    }
    if (proto_p.misa_oneof_case() == ProcessorConfig::kMisa) {
        p.misa = proto_p.misa();
    }
    if (proto_p.mie_oneof_case() == ProcessorConfig::kMie) {
        p.mie = proto_p.mie();
    }
    if (proto_p.mip_oneof_case() == ProcessorConfig::kMip) {
        p.mip = proto_p.mip();
    }
    if (proto_p.medeleg_oneof_case() == ProcessorConfig::kMedeleg) {
        p.medeleg = proto_p.medeleg();
    }
    if (proto_p.mideleg_oneof_case() == ProcessorConfig::kMideleg) {
        p.mideleg = proto_p.mideleg();
    }
    if (proto_p.mcounteren_oneof_case() == ProcessorConfig::kMcounteren) {
        p.mcounteren = proto_p.mcounteren();
    }
    if (proto_p.stvec_oneof_case() == ProcessorConfig::kStvec) {
        p.stvec = proto_p.stvec();
    }
    if (proto_p.sscratch_oneof_case() == ProcessorConfig::kSscratch) {
        p.sscratch = proto_p.sscratch();
    }
    if (proto_p.sepc_oneof_case() == ProcessorConfig::kSepc) {
        p.sepc = proto_p.sepc();
    }
    if (proto_p.scause_oneof_case() == ProcessorConfig::kScause) {
        p.scause = proto_p.scause();
    }
    if (proto_p.stval_oneof_case() == ProcessorConfig::kStval) {
        p.stval = proto_p.stval();
    }
    if (proto_p.satp_oneof_case() == ProcessorConfig::kSatp) {
        p.satp = proto_p.satp();
    }
    if (proto_p.scounteren_oneof_case() == ProcessorConfig::kScounteren) {
        p.scounteren = proto_p.scounteren();
    }
    if (proto_p.ilrsc_oneof_case() == ProcessorConfig::kIlrsc) {
        p.ilrsc = proto_p.ilrsc();
    }
    if (proto_p.iflags_oneof_case() == ProcessorConfig::kIflags) {
        p.iflags = proto_p.iflags();
    }
    return p;
}

flash_drive_config get_proto_flash_drive_config(
    const CartesiMachine::FlashDriveConfig &proto_f) {
    flash_drive_config f;
    f.start = proto_f.start();
    f.image_filename = proto_f.image_filename();
    f.length = proto_f.length();
    f.shared = proto_f.shared();
    return f;
}

machine_runtime_config get_proto_machine_runtime_config(
    const CartesiMachine::MachineRuntimeConfig &proto_r) {
    machine_runtime_config r;
    r.dhd.source_address = proto_r.dhd().source_address();
    r.concurrency.update_merkle_tree = proto_r.concurrency().update_merkle_tree();
    return r;
}

machine_config get_proto_machine_config(
    const CartesiMachine::MachineConfig &proto_c) {
    machine_config c;
    if (proto_c.has_processor()) {
        c.processor = get_proto_processor_config(proto_c.processor());
    }
    if (proto_c.has_rom()) {
        c.rom.bootargs = proto_c.rom().bootargs();
        c.rom.image_filename = proto_c.rom().image_filename();
    }
    if (proto_c.has_ram()) {
        c.ram.length = proto_c.ram().length();
        c.ram.image_filename = proto_c.ram().image_filename();
    }
    for (const auto &fs: proto_c.flash_drive()) {
        c.flash_drive.emplace_back(get_proto_flash_drive_config(fs));
    }
    if (proto_c.has_clint()) {
        const auto &clint = proto_c.clint();
        if (clint.mtimecmp_oneof_case() ==
            CartesiMachine::CLINTConfig::kMtimecmp) {
            c.clint.mtimecmp = clint.mtimecmp();
        }
    }
    if (proto_c.has_htif()) {
        const auto &htif = proto_c.htif();
        if (htif.fromhost() == CartesiMachine::HTIFConfig::kFromhost) {
            c.htif.fromhost = htif.fromhost();
        }
        if (htif.tohost() == CartesiMachine::HTIFConfig::kTohost) {
            c.htif.tohost = htif.tohost();
        }
        // zero default when missing is ok
        c.htif.console_getchar = htif.console_getchar();
        // zero default when missing is ok
        c.htif.yield_progress = htif.yield_progress();
        // zero default when missing is ok
        c.htif.yield_rollup = htif.yield_rollup();
    }
    if (proto_c.has_dhd()) {
        const auto &dhd = proto_c.dhd();
        // zero default when missing is ok
        c.dhd.tstart = dhd.tstart();
        // zero default when missing is ok
        c.dhd.tlength = dhd.tlength();
        c.dhd.image_filename = dhd.image_filename();
        // zero default when missing is ok
        c.dhd.dlength = dhd.dlength();
        // zero default when missing is ok
        c.dhd.hlength = dhd.hlength();
        if (dhd.h_size() > DHD_H_REG_COUNT) {
            throw std::invalid_argument{"too many DHD h registers"};
        }
        for (int i = 0; i < dhd.h_size(); i++) {
            c.dhd.h[i] = dhd.h(i);
        }
    }
    return c;
}

} // namespace cartesi
