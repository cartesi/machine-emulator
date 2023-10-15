// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#include "protobuf-util.h"

namespace cartesi {

semantic_version get_proto_semantic_version(const Versioning::SemanticVersion &proto_v) {
    semantic_version v;
    v.major = proto_v.major();
    v.minor = proto_v.minor();
    v.patch = proto_v.patch();
    v.pre_release = proto_v.pre_release();
    v.build = proto_v.build();
    return v;
}

void set_proto_memory_range(const memory_range_config &m, CartesiMachine::MemoryRangeConfig *proto_m) {
    proto_m->set_start(m.start);
    proto_m->set_length(m.length);
    proto_m->set_shared(m.shared);
    proto_m->set_image_filename(m.image_filename);
}

void set_proto_rollup(const rollup_config &r, CartesiMachine::RollupConfig *proto_r) {
    set_proto_memory_range(r.rx_buffer, proto_r->mutable_rx_buffer());
    set_proto_memory_range(r.tx_buffer, proto_r->mutable_tx_buffer());
    set_proto_memory_range(r.input_metadata, proto_r->mutable_input_metadata());
    set_proto_memory_range(r.voucher_hashes, proto_r->mutable_voucher_hashes());
    set_proto_memory_range(r.notice_hashes, proto_r->mutable_notice_hashes());
}

void set_proto_machine_config(const machine_config &c, CartesiMachine::MachineConfig *proto_c) {
    auto *proto_dtb = proto_c->mutable_dtb();
    proto_dtb->set_bootargs(c.dtb.bootargs);
    proto_dtb->set_image_filename(c.dtb.image_filename);
    auto *proto_ram = proto_c->mutable_ram();
    proto_ram->set_length(c.ram.length);
    proto_ram->set_image_filename(c.ram.image_filename);
    auto *proto_tlb = proto_c->mutable_tlb();
    proto_tlb->set_image_filename(c.tlb.image_filename);
    auto *proto_htif = proto_c->mutable_htif();
    proto_htif->set_console_getchar(c.htif.console_getchar);
    proto_htif->set_yield_manual(c.htif.yield_manual);
    proto_htif->set_yield_automatic(c.htif.yield_automatic);
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
    proto_p->set_f0(c.processor.f[0]);
    proto_p->set_f1(c.processor.f[1]);
    proto_p->set_f2(c.processor.f[2]);
    proto_p->set_f3(c.processor.f[3]);
    proto_p->set_f4(c.processor.f[4]);
    proto_p->set_f5(c.processor.f[5]);
    proto_p->set_f6(c.processor.f[6]);
    proto_p->set_f7(c.processor.f[7]);
    proto_p->set_f8(c.processor.f[8]);
    proto_p->set_f9(c.processor.f[9]);
    proto_p->set_f10(c.processor.f[10]);
    proto_p->set_f11(c.processor.f[11]);
    proto_p->set_f12(c.processor.f[12]);
    proto_p->set_f13(c.processor.f[13]);
    proto_p->set_f14(c.processor.f[14]);
    proto_p->set_f15(c.processor.f[15]);
    proto_p->set_f16(c.processor.f[16]);
    proto_p->set_f17(c.processor.f[17]);
    proto_p->set_f18(c.processor.f[18]);
    proto_p->set_f19(c.processor.f[19]);
    proto_p->set_f20(c.processor.f[20]);
    proto_p->set_f21(c.processor.f[21]);
    proto_p->set_f22(c.processor.f[22]);
    proto_p->set_f23(c.processor.f[23]);
    proto_p->set_f24(c.processor.f[24]);
    proto_p->set_f25(c.processor.f[25]);
    proto_p->set_f26(c.processor.f[26]);
    proto_p->set_f27(c.processor.f[27]);
    proto_p->set_f28(c.processor.f[28]);
    proto_p->set_f29(c.processor.f[29]);
    proto_p->set_f30(c.processor.f[30]);
    proto_p->set_f31(c.processor.f[31]);
    proto_p->set_pc(c.processor.pc);
    proto_p->set_fcsr(c.processor.fcsr);
    proto_p->set_mvendorid(c.processor.mvendorid);
    proto_p->set_marchid(c.processor.marchid);
    proto_p->set_mimpid(c.processor.mimpid);
    proto_p->set_mcycle(c.processor.mcycle);
    proto_p->set_icycleinstret(c.processor.icycleinstret);
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
    proto_p->set_menvcfg(c.processor.menvcfg);
    proto_p->set_stvec(c.processor.stvec);
    proto_p->set_sscratch(c.processor.sscratch);
    proto_p->set_sepc(c.processor.sepc);
    proto_p->set_scause(c.processor.scause);
    proto_p->set_stval(c.processor.stval);
    proto_p->set_satp(c.processor.satp);
    proto_p->set_scounteren(c.processor.scounteren);
    proto_p->set_senvcfg(c.processor.senvcfg);
    proto_p->set_hstatus(c.processor.hstatus);
    proto_p->set_hedeleg(c.processor.hedeleg);
    proto_p->set_hideleg(c.processor.hideleg);
    proto_p->set_hie(c.processor.hie);
    proto_p->set_hip(c.processor.hip);
    proto_p->set_hvip(c.processor.hvip);
    proto_p->set_hgatp(c.processor.hgatp);
    proto_p->set_henvcfg(c.processor.henvcfg);
    proto_p->set_htimedelta(c.processor.htimedelta);
    proto_p->set_htval(c.processor.htval);
    proto_p->set_vsepc(c.processor.vsepc);
    proto_p->set_vsstatus(c.processor.vsstatus);
    proto_p->set_vscause(c.processor.vscause);
    proto_p->set_vstval(c.processor.vstval);
    proto_p->set_vstvec(c.processor.vstvec);
    proto_p->set_vsscratch(c.processor.vsscratch);
    proto_p->set_vsatp(c.processor.vsatp);
    proto_p->set_vsie(c.processor.vsie);
    proto_p->set_vsip(c.processor.vsip);
    proto_p->set_ilrsc(c.processor.ilrsc);
    proto_p->set_iflags(c.processor.iflags);
    for (const auto &f : c.flash_drive) {
        auto *proto_f = proto_c->add_flash_drive();
        set_proto_memory_range(f, proto_f);
    }
    if (c.rollup.has_value()) {
        set_proto_rollup(*c.rollup, proto_c->mutable_rollup());
    }
    auto *proto_u = proto_c->mutable_uarch();
    auto *proto_up = proto_u->mutable_processor();
    proto_up->set_x1(c.uarch.processor.x[1]);
    proto_up->set_x2(c.uarch.processor.x[2]);
    proto_up->set_x3(c.uarch.processor.x[3]);
    proto_up->set_x4(c.uarch.processor.x[4]);
    proto_up->set_x5(c.uarch.processor.x[5]);
    proto_up->set_x6(c.uarch.processor.x[6]);
    proto_up->set_x7(c.uarch.processor.x[7]);
    proto_up->set_x8(c.uarch.processor.x[8]);
    proto_up->set_x9(c.uarch.processor.x[9]);
    proto_up->set_x10(c.uarch.processor.x[10]);
    proto_up->set_x11(c.uarch.processor.x[11]);
    proto_up->set_x12(c.uarch.processor.x[12]);
    proto_up->set_x13(c.uarch.processor.x[13]);
    proto_up->set_x14(c.uarch.processor.x[14]);
    proto_up->set_x15(c.uarch.processor.x[15]);
    proto_up->set_x16(c.uarch.processor.x[16]);
    proto_up->set_x17(c.uarch.processor.x[17]);
    proto_up->set_x18(c.uarch.processor.x[18]);
    proto_up->set_x19(c.uarch.processor.x[19]);
    proto_up->set_x20(c.uarch.processor.x[20]);
    proto_up->set_x21(c.uarch.processor.x[21]);
    proto_up->set_x22(c.uarch.processor.x[22]);
    proto_up->set_x23(c.uarch.processor.x[23]);
    proto_up->set_x24(c.uarch.processor.x[24]);
    proto_up->set_x25(c.uarch.processor.x[25]);
    proto_up->set_x26(c.uarch.processor.x[26]);
    proto_up->set_x27(c.uarch.processor.x[27]);
    proto_up->set_x28(c.uarch.processor.x[28]);
    proto_up->set_x29(c.uarch.processor.x[29]);
    proto_up->set_x30(c.uarch.processor.x[30]);
    proto_up->set_x31(c.uarch.processor.x[31]);
    proto_up->set_pc(c.uarch.processor.pc);
    proto_up->set_cycle(c.uarch.processor.cycle);
    auto *proto_uarch_ram = proto_u->mutable_ram();
    proto_uarch_ram->set_length(c.uarch.ram.length);
    proto_uarch_ram->set_image_filename(c.uarch.ram.image_filename);
}

void set_proto_machine_runtime_config(const machine_runtime_config &r, CartesiMachine::MachineRuntimeConfig *proto_r) {
    auto *proto_concurrency = proto_r->mutable_concurrency();
    proto_concurrency->set_update_merkle_tree(r.concurrency.update_merkle_tree);
}

access_log::type get_proto_log_type(const CartesiMachine::AccessLogType &proto_lt) {
    return access_log::type{proto_lt.proofs(), proto_lt.annotations()};
}

void set_proto_hash(const machine_merkle_tree::hash_type &h, CartesiMachine::Hash *proto_h) {
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

machine_merkle_tree::proof_type get_proto_merkle_tree_proof(const CartesiMachine::MerkleTreeProof &proto_proof) {
    const int log2_target_size = static_cast<int>(proto_proof.log2_target_size());
    const int log2_root_size = static_cast<int>(proto_proof.log2_root_size());
    machine_merkle_tree::proof_type p{log2_root_size, log2_target_size};
    p.set_target_address(proto_proof.target_address());
    p.set_target_hash(get_proto_hash(proto_proof.target_hash()));
    p.set_root_hash(get_proto_hash(proto_proof.root_hash()));
    const auto &proto_sibs = proto_proof.sibling_hashes();
    if (log2_root_size - proto_sibs.size() != log2_target_size) {
        throw std::invalid_argument("wrong number of sibling hashes");
    }
    for (int i = 0; i < proto_sibs.size(); i++) {
        p.set_sibling_hash(get_proto_hash(proto_sibs[i]), log2_root_size - 1 - i);
    }
    return p;
}

void set_proto_merkle_tree_proof(const machine_merkle_tree::proof_type &p, CartesiMachine::MerkleTreeProof *proto_p) {
    proto_p->set_target_address(p.get_target_address());
    proto_p->set_log2_target_size(p.get_log2_target_size());
    proto_p->set_log2_root_size(p.get_log2_root_size());
    set_proto_hash(p.get_target_hash(), proto_p->mutable_target_hash());
    set_proto_hash(p.get_root_hash(), proto_p->mutable_root_hash());
    for (int log2_size = p.get_log2_root_size() - 1; log2_size >= p.get_log2_target_size(); --log2_size) {
        set_proto_hash(p.get_sibling_hash(log2_size), proto_p->add_sibling_hashes());
    }
}

void set_proto_access_log(const access_log &al, CartesiMachine::AccessLog *proto_al) {
    proto_al->mutable_log_type()->set_annotations(al.get_log_type().has_annotations());
    proto_al->mutable_log_type()->set_proofs(al.get_log_type().has_proofs());
    for (const auto &a : al.get_accesses()) {
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
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            set_proto_merkle_tree_proof(a.get_proof().value(), proto_a->mutable_proof());
        }
    }
    if (al.get_log_type().has_annotations()) {
        for (const auto &bn : al.get_brackets()) {
            auto *proto_bn = proto_al->add_brackets();
            switch (bn.type) {
                case bracket_type::begin:
                    proto_bn->set_type(CartesiMachine::BracketNote_BracketNoteType_BEGIN);
                    break;
                case bracket_type::end:
                    proto_bn->set_type(CartesiMachine::BracketNote_BracketNoteType_END);
                    break;
                default:
                    throw std::invalid_argument{"invalid BracketNoteType"};
                    break;
            }
            proto_bn->set_where(bn.where);
            proto_bn->set_text(bn.text);
        }
        for (const auto &n : al.get_notes()) {
            proto_al->add_notes()->assign(n);
        }
    }
}

bracket_type get_proto_bracket_type(CartesiMachine::BracketNote_BracketNoteType proto_b) {
    switch (proto_b) {
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
    if (proto_al.log_type().annotations() && proto_al.accesses().size() != proto_al.notes().size()) {
        throw std::invalid_argument("size of log accesses and notes differ");
    }

    const bool has_annotations = proto_al.log_type().annotations();
    const bool has_proofs = proto_al.log_type().proofs();
    auto al = access_log(access_log::type{has_proofs, has_annotations});

    const auto &proto_accesses = proto_al.accesses();
    const auto &proto_brackets = proto_al.brackets();
    const auto &proto_notes = proto_al.notes();
    auto pbr = proto_brackets.begin();
    auto pnt = proto_notes.begin();
    auto pac = proto_accesses.begin();
    uint64_t iac = 0; // curent access index
    while (pac != proto_accesses.end() && pbr != proto_brackets.end()) {
        while (pbr != proto_brackets.end() && pbr->where() == iac) {
            // bracket note points to current access
            al.push_bracket(get_proto_bracket_type(pbr->type()), pbr->text().c_str());
            assert(pbr->where() == al.get_brackets().back().where);
            pbr++;
        }
        if (pac != proto_accesses.end()) {
            access a;
            a.set_type(get_proto_access_type(pac->type()));
            a.set_address(pac->address());
            a.set_log2_size(static_cast<int>(pac->log2_size()));
            a.get_read().insert(a.get_read().end(), pac->read().begin(), pac->read().end());
            a.get_written().insert(a.get_written().end(), pac->written().begin(), pac->written().end());
            std::string note;
            if (has_annotations) {
                note = *pnt++;
            }
            if (has_proofs) {
                a.set_proof(get_proto_merkle_tree_proof(pac->proof()));
            }
            al.push_access(a, note.c_str());
            pac++;
            iac++;
        }
    }
    // push closing bracket notes
    while (pbr != proto_brackets.end()) {
        al.push_bracket(get_proto_bracket_type(pbr->type()), pbr->text().c_str());
        assert(pbr->where() == al.get_brackets().back().where);
        pbr++;
    }
    return al;
}

processor_config get_proto_processor_config(const CartesiMachine::ProcessorConfig &proto_p) {
    using CartesiMachine::ProcessorConfig;
    processor_config p;
    if (proto_p.has_x1()) {
        p.x[1] = proto_p.x1();
    }
    if (proto_p.has_x2()) {
        p.x[2] = proto_p.x2();
    }
    if (proto_p.has_x3()) {
        p.x[3] = proto_p.x3();
    }
    if (proto_p.has_x4()) {
        p.x[4] = proto_p.x4();
    }
    if (proto_p.has_x5()) {
        p.x[5] = proto_p.x5();
    }
    if (proto_p.has_x6()) {
        p.x[6] = proto_p.x6();
    }
    if (proto_p.has_x7()) {
        p.x[7] = proto_p.x7();
    }
    if (proto_p.has_x8()) {
        p.x[8] = proto_p.x8();
    }
    if (proto_p.has_x9()) {
        p.x[9] = proto_p.x9();
    }
    if (proto_p.has_x10()) {
        p.x[10] = proto_p.x10();
    }
    if (proto_p.has_x11()) {
        p.x[11] = proto_p.x11();
    }
    if (proto_p.has_x12()) {
        p.x[12] = proto_p.x12();
    }
    if (proto_p.has_x13()) {
        p.x[13] = proto_p.x13();
    }
    if (proto_p.has_x14()) {
        p.x[14] = proto_p.x14();
    }
    if (proto_p.has_x15()) {
        p.x[15] = proto_p.x15();
    }
    if (proto_p.has_x16()) {
        p.x[16] = proto_p.x16();
    }
    if (proto_p.has_x17()) {
        p.x[17] = proto_p.x17();
    }
    if (proto_p.has_x18()) {
        p.x[18] = proto_p.x18();
    }
    if (proto_p.has_x19()) {
        p.x[19] = proto_p.x19();
    }
    if (proto_p.has_x20()) {
        p.x[20] = proto_p.x20();
    }
    if (proto_p.has_x21()) {
        p.x[21] = proto_p.x21();
    }
    if (proto_p.has_x22()) {
        p.x[22] = proto_p.x22();
    }
    if (proto_p.has_x23()) {
        p.x[23] = proto_p.x23();
    }
    if (proto_p.has_x24()) {
        p.x[24] = proto_p.x24();
    }
    if (proto_p.has_x25()) {
        p.x[25] = proto_p.x25();
    }
    if (proto_p.has_x26()) {
        p.x[26] = proto_p.x26();
    }
    if (proto_p.has_x27()) {
        p.x[27] = proto_p.x27();
    }
    if (proto_p.has_x28()) {
        p.x[28] = proto_p.x28();
    }
    if (proto_p.has_x29()) {
        p.x[29] = proto_p.x29();
    }
    if (proto_p.has_x30()) {
        p.x[30] = proto_p.x30();
    }
    if (proto_p.has_x31()) {
        p.x[31] = proto_p.x31();
    }
    if (proto_p.has_f0()) {
        p.f[0] = proto_p.f0();
    }
    if (proto_p.has_f1()) {
        p.f[1] = proto_p.f1();
    }
    if (proto_p.has_f2()) {
        p.f[2] = proto_p.f2();
    }
    if (proto_p.has_f3()) {
        p.f[3] = proto_p.f3();
    }
    if (proto_p.has_f4()) {
        p.f[4] = proto_p.f4();
    }
    if (proto_p.has_f5()) {
        p.f[5] = proto_p.f5();
    }
    if (proto_p.has_f6()) {
        p.f[6] = proto_p.f6();
    }
    if (proto_p.has_f7()) {
        p.f[7] = proto_p.f7();
    }
    if (proto_p.has_f8()) {
        p.f[8] = proto_p.f8();
    }
    if (proto_p.has_f9()) {
        p.f[9] = proto_p.f9();
    }
    if (proto_p.has_f10()) {
        p.f[10] = proto_p.f10();
    }
    if (proto_p.has_f11()) {
        p.f[11] = proto_p.f11();
    }
    if (proto_p.has_f12()) {
        p.f[12] = proto_p.f12();
    }
    if (proto_p.has_f13()) {
        p.f[13] = proto_p.f13();
    }
    if (proto_p.has_f14()) {
        p.f[14] = proto_p.f14();
    }
    if (proto_p.has_f15()) {
        p.f[15] = proto_p.f15();
    }
    if (proto_p.has_f16()) {
        p.f[16] = proto_p.f16();
    }
    if (proto_p.has_f17()) {
        p.f[17] = proto_p.f17();
    }
    if (proto_p.has_f18()) {
        p.f[18] = proto_p.f18();
    }
    if (proto_p.has_f19()) {
        p.f[19] = proto_p.f19();
    }
    if (proto_p.has_f20()) {
        p.f[20] = proto_p.f20();
    }
    if (proto_p.has_f21()) {
        p.f[21] = proto_p.f21();
    }
    if (proto_p.has_f22()) {
        p.f[22] = proto_p.f22();
    }
    if (proto_p.has_f23()) {
        p.f[23] = proto_p.f23();
    }
    if (proto_p.has_f24()) {
        p.f[24] = proto_p.f24();
    }
    if (proto_p.has_f25()) {
        p.f[25] = proto_p.f25();
    }
    if (proto_p.has_f26()) {
        p.f[26] = proto_p.f26();
    }
    if (proto_p.has_f27()) {
        p.f[27] = proto_p.f27();
    }
    if (proto_p.has_f28()) {
        p.f[28] = proto_p.f28();
    }
    if (proto_p.has_f29()) {
        p.f[29] = proto_p.f29();
    }
    if (proto_p.has_f30()) {
        p.f[30] = proto_p.f30();
    }
    if (proto_p.has_f31()) {
        p.f[31] = proto_p.f31();
    }
    if (proto_p.has_pc()) {
        p.pc = proto_p.pc();
    }
    if (proto_p.has_fcsr()) {
        p.fcsr = proto_p.fcsr();
    }
    if (proto_p.has_mvendorid()) {
        p.mvendorid = proto_p.mvendorid();
    }
    if (proto_p.has_marchid()) {
        p.marchid = proto_p.marchid();
    }
    if (proto_p.has_mimpid()) {
        p.mimpid = proto_p.mimpid();
    }
    if (proto_p.has_mcycle()) {
        p.mcycle = proto_p.mcycle();
    }
    if (proto_p.has_icycleinstret()) {
        p.icycleinstret = proto_p.icycleinstret();
    }
    if (proto_p.has_mstatus()) {
        p.mstatus = proto_p.mstatus();
    }
    if (proto_p.has_mtvec()) {
        p.mtvec = proto_p.mtvec();
    }
    if (proto_p.has_mscratch()) {
        p.mscratch = proto_p.mscratch();
    }
    if (proto_p.has_mepc()) {
        p.mepc = proto_p.mepc();
    }
    if (proto_p.has_mcause()) {
        p.mcause = proto_p.mcause();
    }
    if (proto_p.has_mtval()) {
        p.mtval = proto_p.mtval();
    }
    if (proto_p.has_misa()) {
        p.misa = proto_p.misa();
    }
    if (proto_p.has_mie()) {
        p.mie = proto_p.mie();
    }
    if (proto_p.has_mip()) {
        p.mip = proto_p.mip();
    }
    if (proto_p.has_medeleg()) {
        p.medeleg = proto_p.medeleg();
    }
    if (proto_p.has_mideleg()) {
        p.mideleg = proto_p.mideleg();
    }
    if (proto_p.has_mcounteren()) {
        p.mcounteren = proto_p.mcounteren();
    }
    if (proto_p.has_menvcfg()) {
        p.menvcfg = proto_p.menvcfg();
    }
    if (proto_p.has_stvec()) {
        p.stvec = proto_p.stvec();
    }
    if (proto_p.has_sscratch()) {
        p.sscratch = proto_p.sscratch();
    }
    if (proto_p.has_sepc()) {
        p.sepc = proto_p.sepc();
    }
    if (proto_p.has_scause()) {
        p.scause = proto_p.scause();
    }
    if (proto_p.has_stval()) {
        p.stval = proto_p.stval();
    }
    if (proto_p.has_satp()) {
        p.satp = proto_p.satp();
    }
    if (proto_p.has_scounteren()) {
        p.scounteren = proto_p.scounteren();
    }
    if (proto_p.has_senvcfg()) {
        p.senvcfg = proto_p.senvcfg();
    }
    if (proto_p.has_hstatus()) {
        p.hstatus = proto_p.hstatus();
    }
    if (proto_p.has_hideleg()) {
        p.hideleg = proto_p.hideleg();
    }
    if (proto_p.has_hedeleg()) {
        p.hedeleg = proto_p.hedeleg();
    }
    if (proto_p.has_hie()) {
        p.hie = proto_p.hie();
    }
    if (proto_p.has_hip()) {
        p.hip = proto_p.hip();
    }
    if (proto_p.has_hvip()) {
        p.hvip = proto_p.hvip();
    }
    if (proto_p.has_hgatp()) {
        p.hgatp = proto_p.hgatp();
    }
    if (proto_p.has_henvcfg()) {
        p.henvcfg = proto_p.henvcfg();
    }
    if (proto_p.has_htimedelta()) {
        p.htimedelta = proto_p.htimedelta();
    }
    if (proto_p.has_htval()) {
        p.htval = proto_p.htval();
    }
    if (proto_p.has_vsepc()) {
        p.vsepc = proto_p.vsepc();
    }
    if (proto_p.has_vsstatus()) {
        p.vsstatus = proto_p.vsstatus();
    }
    if (proto_p.has_vscause()) {
        p.vscause = proto_p.vscause();
    }
    if (proto_p.has_vstval()) {
        p.vstval = proto_p.vstval();
    }
    if (proto_p.has_vstvec()) {
        p.vstvec = proto_p.vstvec();
    }
    if (proto_p.has_vsscratch()) {
        p.vsscratch = proto_p.vsscratch();
    }
    if (proto_p.has_vsatp()) {
        p.vsatp = proto_p.vsatp();
    }
    if (proto_p.has_vsie()) {
        p.vsie = proto_p.vsie();
    }
    if (proto_p.has_vsip()) {
        p.vsip = proto_p.vsip();
    }
    if (proto_p.has_ilrsc()) {
        p.ilrsc = proto_p.ilrsc();
    }
    if (proto_p.has_iflags()) {
        p.iflags = proto_p.iflags();
    }
    return p;
}

memory_range_config get_proto_memory_range_config(const CartesiMachine::MemoryRangeConfig &proto_m) {
    memory_range_config m;
    m.start = proto_m.start();
    m.image_filename = proto_m.image_filename();
    m.length = proto_m.length();
    m.shared = proto_m.shared();
    return m;
}

machine_runtime_config get_proto_machine_runtime_config(const CartesiMachine::MachineRuntimeConfig &proto_r) {
    machine_runtime_config r;
    r.concurrency.update_merkle_tree = proto_r.concurrency().update_merkle_tree();
    return r;
}

static uarch_config get_proto_uarch_config(const CartesiMachine::UarchConfig &proto_c) {
    using CartesiMachine::UarchConfig;
    uarch_config c;
    if (proto_c.has_ram()) {
        c.ram.length = proto_c.ram().length();
        c.ram.image_filename = proto_c.ram().image_filename();
    }
    if (proto_c.has_processor()) {
        const auto &proto_p = proto_c.processor();
        auto &p = c.processor;
        if (proto_p.has_x1()) {
            p.x[1] = proto_p.x1();
        }
        if (proto_p.has_x2()) {
            p.x[2] = proto_p.x2();
        }
        if (proto_p.has_x3()) {
            p.x[3] = proto_p.x3();
        }
        if (proto_p.has_x4()) {
            p.x[4] = proto_p.x4();
        }
        if (proto_p.has_x5()) {
            p.x[5] = proto_p.x5();
        }
        if (proto_p.has_x6()) {
            p.x[6] = proto_p.x6();
        }
        if (proto_p.has_x7()) {
            p.x[7] = proto_p.x7();
        }
        if (proto_p.has_x8()) {
            p.x[8] = proto_p.x8();
        }
        if (proto_p.has_x9()) {
            p.x[9] = proto_p.x9();
        }
        if (proto_p.has_x10()) {
            p.x[10] = proto_p.x10();
        }
        if (proto_p.has_x11()) {
            p.x[11] = proto_p.x11();
        }
        if (proto_p.has_x12()) {
            p.x[12] = proto_p.x12();
        }
        if (proto_p.has_x13()) {
            p.x[13] = proto_p.x13();
        }
        if (proto_p.has_x14()) {
            p.x[14] = proto_p.x14();
        }
        if (proto_p.has_x15()) {
            p.x[15] = proto_p.x15();
        }
        if (proto_p.has_x16()) {
            p.x[16] = proto_p.x16();
        }
        if (proto_p.has_x17()) {
            p.x[17] = proto_p.x17();
        }
        if (proto_p.has_x18()) {
            p.x[18] = proto_p.x18();
        }
        if (proto_p.has_x19()) {
            p.x[19] = proto_p.x19();
        }
        if (proto_p.has_x20()) {
            p.x[20] = proto_p.x20();
        }
        if (proto_p.has_x21()) {
            p.x[21] = proto_p.x21();
        }
        if (proto_p.has_x22()) {
            p.x[22] = proto_p.x22();
        }
        if (proto_p.has_x23()) {
            p.x[23] = proto_p.x23();
        }
        if (proto_p.has_x24()) {
            p.x[24] = proto_p.x24();
        }
        if (proto_p.has_x25()) {
            p.x[25] = proto_p.x25();
        }
        if (proto_p.has_x26()) {
            p.x[26] = proto_p.x26();
        }
        if (proto_p.has_x27()) {
            p.x[27] = proto_p.x27();
        }
        if (proto_p.has_x28()) {
            p.x[28] = proto_p.x28();
        }
        if (proto_p.has_x29()) {
            p.x[29] = proto_p.x29();
        }
        if (proto_p.has_x30()) {
            p.x[30] = proto_p.x30();
        }
        if (proto_p.has_x31()) {
            p.x[31] = proto_p.x31();
        }
        if (proto_p.has_pc()) {
            p.pc = proto_p.pc();
        }
        if (proto_p.has_cycle()) {
            p.cycle = proto_p.cycle();
        }
    }
    return c;
}

rollup_config get_proto_rollup_config(const CartesiMachine::RollupConfig &proto_r) {
    rollup_config r;
    if (proto_r.has_rx_buffer()) {
        r.rx_buffer = get_proto_memory_range_config(proto_r.rx_buffer());
    }
    if (proto_r.has_tx_buffer()) {
        r.tx_buffer = get_proto_memory_range_config(proto_r.tx_buffer());
    }
    if (proto_r.has_input_metadata()) {
        r.input_metadata = get_proto_memory_range_config(proto_r.input_metadata());
    }
    if (proto_r.has_voucher_hashes()) {
        r.voucher_hashes = get_proto_memory_range_config(proto_r.voucher_hashes());
    }
    if (proto_r.has_input_metadata()) {
        r.notice_hashes = get_proto_memory_range_config(proto_r.notice_hashes());
    }
    return r;
}

machine_config get_proto_machine_config(const CartesiMachine::MachineConfig &proto_c) {
    machine_config c;
    if (proto_c.has_processor()) {
        c.processor = get_proto_processor_config(proto_c.processor());
    }
    if (proto_c.has_uarch()) {
        c.uarch = get_proto_uarch_config(proto_c.uarch());
    }
    if (proto_c.has_dtb()) {
        c.dtb.bootargs = proto_c.dtb().bootargs();
        c.dtb.image_filename = proto_c.dtb().image_filename();
    }
    if (proto_c.has_ram()) {
        c.ram.length = proto_c.ram().length();
        c.ram.image_filename = proto_c.ram().image_filename();
    }
    for (const auto &fs : proto_c.flash_drive()) {
        c.flash_drive.emplace_back(get_proto_memory_range_config(fs));
    }
    if (proto_c.has_rollup()) {
        c.rollup = get_proto_rollup_config(proto_c.rollup());
    }
    if (proto_c.has_tlb()) {
        c.tlb.image_filename = proto_c.tlb().image_filename();
    }
    if (proto_c.has_clint()) {
        const auto &clint = proto_c.clint();
        if (clint.has_mtimecmp()) {
            c.clint.mtimecmp = clint.mtimecmp();
        }
    }
    if (proto_c.has_htif()) {
        const auto &htif = proto_c.htif();
        if (htif.has_fromhost()) {
            c.htif.fromhost = htif.fromhost();
        }
        if (htif.has_tohost()) {
            c.htif.tohost = htif.tohost();
        }

        // zero default when missing is ok
        c.htif.console_getchar = htif.console_getchar();
        // zero default when missing is ok
        c.htif.yield_manual = htif.yield_manual();
        // zero default when missing is ok
        c.htif.yield_automatic = htif.yield_automatic();
    }
    return c;
}

} // namespace cartesi
