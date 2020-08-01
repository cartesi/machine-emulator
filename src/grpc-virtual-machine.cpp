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

#include <cstdint>
#include <string>
#include <algorithm>

#include "grpc-virtual-machine.h"

using grpc::Channel;
using grpc::Status;
using grpc::ClientContext;
using CartesiMachine::Machine;
using CartesiMachine::Void;
using CartesiMachine::Machine;
using CartesiMachine::VerifyMerkleTreeResponse;
using CartesiMachine::UpdateMerkleTreeResponse;
using CartesiMachine::VerifyDirtyPageMapsResponse;
using CartesiMachine::MachineConfig;
using CartesiMachine::GetInitialConfigResponse;
using CartesiMachine::ProcessorConfig;
using CartesiMachine::HTIFConfig;
using CartesiMachine::ROMConfig;
using CartesiMachine::RAMConfig;
using CartesiMachine::FlashDriveConfig;
using CartesiMachine::CLINTConfig;
using CartesiMachine::HTIFConfig;
using CartesiMachine::ReplaceFlashDriveRequest;
using CartesiMachine::FlashDriveConfig;
using CartesiMachine::MachineRequest;
using CartesiMachine::MachineRequest;
using CartesiMachine::RunRequest;
using CartesiMachine::RunResponse;
using CartesiMachine::Csr;
using CartesiMachine::ReadCsrRequest;
using CartesiMachine::ReadCsrResponse;
using CartesiMachine::WriteCsrRequest;
using CartesiMachine::StepResponse;
using CartesiMachine::GetCsrAddressRequest;
using CartesiMachine::GetCsrAddressResponse;
using CartesiMachine::ReadXRequest;
using CartesiMachine::ReadXResponse;
using CartesiMachine::GetXAddressRequest;
using CartesiMachine::GetXAddressResponse;
using CartesiMachine::WriteXRequest;
using CartesiMachine::StoreRequest;
using CartesiMachine::ReadWordRequest;
using CartesiMachine::ReadWordResponse;
using CartesiMachine::WriteMemoryRequest;
using CartesiMachine::ReadMemoryRequest;
using CartesiMachine::ReadMemoryResponse;
using CartesiMachine::GetRootHashResponse;
using CartesiMachine::AccessOperation;
using CartesiMachine::Hash;
using CartesiMachine::GetProofRequest;
using CartesiMachine::Word;
using CartesiMachine::GetProofResponse;
using CartesiMachine::Proof;
using CartesiMachine::StepRequest;
using CartesiMachine::AccessLog;
using CartesiMachine::AccessLogType;
using CartesiMachine::Access;
using CartesiMachine::BracketNote;
using CartesiMachine::BracketNote_BracketNoteType;
using CartesiMachine::BracketNote_BracketNoteType_BEGIN;
using CartesiMachine::BracketNote_BracketNoteType_END;
using hash_type = cartesi::merkle_tree::hash_type;

namespace cartesi {

static void check_status(const Status &status) {
    if (!status.ok()) {
        throw std::runtime_error(status.error_message());
    }
}

grpc_virtual_machine::grpc_virtual_machine(const std::string &address, const std::string &dir) {
    m_stub = Machine::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    create_machine(dir);
}

grpc_virtual_machine::grpc_virtual_machine(const std::string &address, const machine_config &c) {
    m_stub = Machine::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    create_machine(c);
}

grpc_virtual_machine::~grpc_virtual_machine(void) {
}

void grpc_virtual_machine::create_machine(const std::string &dir) {
    MachineRequest request;
    request.set_directory(dir);
    Void response;
    ClientContext context;
    check_status(m_stub->Machine(&context, request, &response));
}

void grpc_virtual_machine::create_machine(const machine_config &c) {
    MachineRequest request;
    MachineConfig* cfg = request.mutable_config();
    ROMConfig *rom = cfg->mutable_rom();
    rom->set_bootargs(c.rom.bootargs);
    rom->set_image_filename(c.rom.image_filename);
    RAMConfig* ram = cfg->mutable_ram();
    ram->set_length(c.ram.length);
    ram->set_image_filename(c.ram.image_filename);
    HTIFConfig* htif = cfg->mutable_htif();
    htif->set_console_getchar(c.htif.console_getchar);
    htif->set_yield_progress(c.htif.yield_progress);
    htif->set_yield_rollup(c.htif.yield_rollup);
    htif->set_fromhost(c.htif.fromhost);
    htif->set_tohost(c.htif.tohost);
    CLINTConfig* clint = cfg->mutable_clint();
    clint->set_mtimecmp(c.clint.mtimecmp);
    ProcessorConfig* p = cfg->mutable_processor();
    p->set_x1(c.processor.x[1]);
    p->set_x2(c.processor.x[2]);
    p->set_x3(c.processor.x[3]);
    p->set_x4(c.processor.x[4]);
    p->set_x5(c.processor.x[5]);
    p->set_x6(c.processor.x[6]);
    p->set_x7(c.processor.x[7]);
    p->set_x8(c.processor.x[8]);
    p->set_x9(c.processor.x[9]);
    p->set_x10(c.processor.x[10]);
    p->set_x11(c.processor.x[11]);
    p->set_x12(c.processor.x[12]);
    p->set_x13(c.processor.x[13]);
    p->set_x14(c.processor.x[14]);
    p->set_x15(c.processor.x[15]);
    p->set_x16(c.processor.x[16]);
    p->set_x17(c.processor.x[17]);
    p->set_x18(c.processor.x[18]);
    p->set_x19(c.processor.x[19]);
    p->set_x20(c.processor.x[20]);
    p->set_x21(c.processor.x[21]);
    p->set_x22(c.processor.x[22]);
    p->set_x23(c.processor.x[23]);
    p->set_x24(c.processor.x[24]);
    p->set_x25(c.processor.x[25]);
    p->set_x26(c.processor.x[26]);
    p->set_x27(c.processor.x[27]);
    p->set_x28(c.processor.x[28]);
    p->set_x29(c.processor.x[29]);
    p->set_x30(c.processor.x[30]);
    p->set_x31(c.processor.x[31]);
    p->set_pc(c.processor.pc);
    p->set_mvendorid(c.processor.mvendorid);
    p->set_marchid(c.processor.marchid);
    p->set_mimpid(c.processor.mimpid);
    p->set_mcycle(c.processor.mcycle);
    p->set_minstret(c.processor.minstret);
    p->set_mstatus(c.processor.mstatus);
    p->set_mtvec(c.processor.mtvec);
    p->set_mscratch(c.processor.mscratch);
    p->set_mepc(c.processor.mepc);
    p->set_mcause(c.processor.mcause);
    p->set_mtval(c.processor.mtval);
    p->set_misa(c.processor.misa);
    p->set_mie(c.processor.mie);
    p->set_mip(c.processor.mip);
    p->set_medeleg(c.processor.medeleg);
    p->set_mideleg(c.processor.mideleg);
    p->set_mcounteren(c.processor.mcounteren);
    p->set_stvec(c.processor.stvec);
    p->set_sscratch(c.processor.sscratch);
    p->set_sepc(c.processor.sepc);
    p->set_scause(c.processor.scause);
    p->set_stval(c.processor.stval);
    p->set_satp(c.processor.satp);
    p->set_scounteren(c.processor.scounteren);
    p->set_ilrsc(c.processor.ilrsc);
    p->set_iflags(c.processor.iflags);
    for(const auto &f:c.flash_drive) {
        auto flash = cfg->add_flash_drive();
        flash->set_start(f.start);
        flash->set_length(f.length);
        flash->set_shared(f.shared);
        flash->set_image_filename(f.image_filename);
    }
    Void response;
    ClientContext context;
    check_status(m_stub->Machine(&context, request, &response));
}

machine_config grpc_virtual_machine::do_get_initial_config(void) {
    Void request;
    GetInitialConfigResponse response;
    ClientContext context;
    check_status(m_stub->GetInitialConfig(&context, request, &response));

    auto &rom = response.config().rom();
    auto &ram = response.config().ram();
    auto &clint = response.config().clint();
    auto &htif = response.config().htif();
    auto &p = response.config().processor();

    processor_config pc;
    pc.pc = p.pc();
    pc.mvendorid = p.mvendorid();
    pc.marchid = p.marchid();
    pc.mimpid = p.mimpid();
    pc.mcycle = p.mcycle();
    pc.minstret = p.minstret();
    pc.mstatus = p.mstatus();
    pc.mtvec = p.mtvec();
    pc.mscratch = p.mscratch();
    pc.mepc = p.mepc();
    pc.mcause = p.mcause();
    pc.mtval = p.mtval();
    pc.misa = p.misa();
    pc.mie = p.mie();
    pc.mip = p.mip();
    pc.medeleg = p.medeleg();
    pc.mideleg = p.mideleg();
    pc.mcounteren = p.mcounteren();
    pc.stvec = p.stvec();
    pc.sscratch = p.sscratch();
    pc.sepc = p.sepc();
    pc.scause = p.scause();
    pc.stval = p.stval();
    pc.satp = p.satp();
    pc.scounteren = p.scounteren();
    pc.ilrsc = p.ilrsc();
    pc.iflags = p.iflags();
    if (p.x1_oneof_case()  == ProcessorConfig::kX1)  pc.x[1] = p.x1();
    if (p.x2_oneof_case()  == ProcessorConfig::kX2)  pc.x[2] = p.x2();
    if (p.x3_oneof_case()  == ProcessorConfig::kX3)  pc.x[3] = p.x3();
    if (p.x4_oneof_case()  == ProcessorConfig::kX4)  pc.x[4] = p.x4();
    if (p.x5_oneof_case()  == ProcessorConfig::kX5)  pc.x[5] = p.x5();
    if (p.x6_oneof_case()  == ProcessorConfig::kX6)  pc.x[6] = p.x6();
    if (p.x7_oneof_case()  == ProcessorConfig::kX7)  pc.x[7] = p.x7();
    if (p.x8_oneof_case()  == ProcessorConfig::kX8)  pc.x[8] = p.x8();
    if (p.x9_oneof_case()  == ProcessorConfig::kX9)  pc.x[9] = p.x9();
    if (p.x10_oneof_case() == ProcessorConfig::kX10) pc.x[10]= p.x10();
    if (p.x11_oneof_case()  == ProcessorConfig::kX11)  pc.x[11] = p.x11();
    if (p.x12_oneof_case()  == ProcessorConfig::kX12)  pc.x[12] = p.x12();
    if (p.x13_oneof_case()  == ProcessorConfig::kX13)  pc.x[13] = p.x13();
    if (p.x14_oneof_case()  == ProcessorConfig::kX14)  pc.x[14] = p.x14();
    if (p.x15_oneof_case()  == ProcessorConfig::kX15)  pc.x[15] = p.x15();
    if (p.x16_oneof_case()  == ProcessorConfig::kX16)  pc.x[16] = p.x16();
    if (p.x17_oneof_case()  == ProcessorConfig::kX17)  pc.x[17] = p.x17();
    if (p.x18_oneof_case()  == ProcessorConfig::kX18)  pc.x[18] = p.x18();
    if (p.x19_oneof_case()  == ProcessorConfig::kX19)  pc.x[19] = p.x19();
    if (p.x20_oneof_case() == ProcessorConfig::kX20)  pc.x[20]= p.x20();
    if (p.x21_oneof_case()  == ProcessorConfig::kX21)  pc.x[21] = p.x21();
    if (p.x22_oneof_case()  == ProcessorConfig::kX22)  pc.x[22] = p.x22();
    if (p.x23_oneof_case()  == ProcessorConfig::kX23)  pc.x[23] = p.x23();
    if (p.x24_oneof_case()  == ProcessorConfig::kX24)  pc.x[24] = p.x24();
    if (p.x25_oneof_case()  == ProcessorConfig::kX25)  pc.x[25] = p.x25();
    if (p.x26_oneof_case()  == ProcessorConfig::kX26)  pc.x[26] = p.x26();
    if (p.x27_oneof_case()  == ProcessorConfig::kX27)  pc.x[27] = p.x27();
    if (p.x28_oneof_case()  == ProcessorConfig::kX28)  pc.x[28] = p.x28();
    if (p.x29_oneof_case()  == ProcessorConfig::kX29)  pc.x[29] = p.x29();
    if (p.x30_oneof_case()  == ProcessorConfig::kX30)  pc.x[30] = p.x30();
    if (p.x31_oneof_case()  == ProcessorConfig::kX31)  pc.x[31] = p.x31();

    if (response.config().flash_drive().size() > FLASH_DRIVE_MAX)
        throw std::invalid_argument{"too many flash drives"};

    flash_drive_configs flashes;
    for(const auto &f: response.config().flash_drive())
        flashes.push_back(flash_drive_config{
            f.start(),
            f.length(),
            f.shared(),
            f.image_filename()});

    return  machine_config{
        pc,
        ram_config{
            ram.length(),
            ram.image_filename()
        },
        rom_config{
            rom.bootargs(),
            rom.image_filename()
        },
        flashes,
        clint_config{
            clint.mtimecmp()
        },
        htif_config{
            htif.fromhost(),
            htif.tohost(),
            htif.console_getchar(),
            htif.yield_progress(),
            htif.yield_rollup()
        }
    };
}

void grpc_virtual_machine::do_run(uint64_t mcycle_end) {
    RunRequest request;
    request.set_limit(mcycle_end);
    RunResponse response;
    ClientContext context;
    check_status(m_stub->Run(&context, request, &response));
}

void grpc_virtual_machine::do_store(const std::string &dir) {
    StoreRequest request;
    request.set_directory(dir);
    Void response;
    ClientContext context;
    check_status(m_stub->Store(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_read_csr(csr r)  {
    ReadCsrRequest request;
    request.set_csr((Csr)r);
    ReadCsrResponse response;
    ClientContext context;
    check_status(m_stub->ReadCsr(&context, request, &response));
    auto name = CartesiMachine::Csr_Name((Csr)r);
    return response.value();
}

void grpc_virtual_machine::do_write_csr(csr w, uint64_t val)   {
    WriteCsrRequest request;
    request.set_csr((Csr)w);
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->WriteCsr(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_get_csr_address(csr w) {
    GetCsrAddressRequest request;
    request.set_csr((Csr)w);
    GetCsrAddressResponse response;
    ClientContext context;
    check_status(m_stub->GetCsrAddress(&context, request, &response));
    return response.address();
}

uint64_t grpc_virtual_machine::do_read_x(int i) {
    ReadXRequest request;
    request.set_index(i);
    ReadXResponse response;
    ClientContext context;
    check_status(m_stub->ReadX(&context, request, &response));
    return response.value();
}

void grpc_virtual_machine::do_write_x(int i, uint64_t val)  {
    WriteXRequest request;
    request.set_index(i);
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->WriteX(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_get_x_address(int i)  {
    GetXAddressRequest request;
    request.set_index(i);
    GetXAddressResponse response;
    ClientContext context;
    check_status(m_stub->GetXAddress(&context, request, &response));
    return response.address();
}

void grpc_virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length)  {
    ReadMemoryRequest request;
    request.set_address(address);
    request.set_length(length);
    ReadMemoryResponse response;
    ClientContext context;
    check_status(m_stub->ReadMemory(&context, request, &response));
    assert(response.data().size() == length);
    memcpy(data, response.data().data(), response.data().size());
}

void grpc_virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, size_t length)  {
    WriteMemoryRequest request;
    request.set_address(address);
    request.set_data(std::string(reinterpret_cast<const char*>(data), length));
    ClientContext context;
    Void response;
    check_status(m_stub->WriteMemory(&context, request, &response));
}

static hash_type make_hash(const Hash& proto_hash) {
    hash_type hash;
    if (proto_hash.data().size() != hash.size())
        throw std::invalid_argument("invalid hash size");
    memcpy(hash.data(), proto_hash.data().data(), proto_hash.data().size());
    return hash;
}

static merkle_tree::proof_type make_proof(const Proof& proto_proof) {
    merkle_tree::proof_type proof;
    proof.address = proto_proof.address();
    proof.log2_size = proto_proof.log2_size();
    if (proof.log2_size > merkle_tree::get_log2_tree_size() ||
        proof.log2_size < merkle_tree::get_log2_word_size())
        throw std::invalid_argument("invalid log2_size");

    proof.target_hash = make_hash(proto_proof.target_hash());
    proof.root_hash = make_hash(proto_proof.root_hash());
    const auto &proto_sibs = proto_proof.sibling_hashes();
    if (proto_sibs.size() + proof.log2_size != merkle_tree::get_log2_tree_size())
        throw std::invalid_argument("too many sibling hashes");

    for(int i=0; i<proto_sibs.size(); i++) {
        proof.sibling_hashes[0] = make_hash(proto_sibs[i]);
    }
    return proof;
}

void grpc_virtual_machine::do_get_root_hash(hash_type &hash)  {
    GetRootHashResponse response;
    Void request;
    ClientContext context;
    check_status(m_stub->GetRootHash(&context, request, &response));
    hash = make_hash(response.hash());
}

void grpc_virtual_machine::do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof)  {
    GetProofRequest request;
    GetProofResponse response;
    request.set_address(address);
    request.set_log2_size(log2_size);
    ClientContext context;
    check_status(m_stub->GetProof(&context, request, &response));
    proof = make_proof(response.proof());
}

void grpc_virtual_machine::do_replace_flash_drive(const flash_drive_config &new_flash)  {
    ReplaceFlashDriveRequest request;
    FlashDriveConfig* flash = request.mutable_config();
    flash->set_start(new_flash.start);
    flash->set_length(new_flash.length);
    flash->set_shared(new_flash.shared);
    flash->set_image_filename(new_flash.image_filename);
    Void response;
    ClientContext context;
    check_status(m_stub->ReplaceFlashDrive(&context, request, &response));
}

static access_type make_access_type(AccessOperation proto_operation) {
    switch (proto_operation) {
        case (AccessOperation::READ):
            return access_type::read;
        case (AccessOperation::WRITE):
            return access_type::write;
        default:
            throw std::invalid_argument{"invalid AccessOperation"};
    };
}

static uint64_t make_word(const Word &proto_word) {
  uint64_t word;
  if (proto_word.data().size() > sizeof(word))
      throw std::runtime_error("word is too big");

  memcpy(&word, proto_word.data().data(), proto_word.data().size());
  return word;
}

static bracket_type make_bracket_type(BracketNote_BracketNoteType proto_bn_type) {
    switch(proto_bn_type) {
        case (BracketNote_BracketNoteType_BEGIN):
            return bracket_type::begin;
        case (BracketNote_BracketNoteType_END):
            return bracket_type::end;
        default:
            throw std::invalid_argument("invalid bracket type");
    }
}

access_log grpc_virtual_machine::do_step(const access_log::type &log_type, bool /*one_based = false*/) {
    StepRequest request;
    request.mutable_log_type()->set_proofs(log_type.has_proofs());
    request.mutable_log_type()->set_annotations(log_type.has_annotations());
    StepResponse response;
    ClientContext context;
    check_status(m_stub->Step(&context, request, &response));

    const auto &proto_al = response.log();
    if (proto_al.log_type().annotations() &&
        proto_al.accesses().size() != proto_al.notes().size())
        throw std::invalid_argument("size of log accesses and notes differ");

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
    while(pac != proto_accesses.end() && pbr != proto_brackets.end()) {
        while (pbr != proto_brackets.end() && pbr->where() == iac) {
            // bracket note points to current access
            al.push_bracket(make_bracket_type(pbr->type()),  pbr->text().c_str());
            assert(pbr->where() == al.get_brackets().back().where);
            pbr++;
        }
        if (pac != proto_accesses.end()) {
            word_access wa;
            wa.type = make_access_type(pac->operation());
            wa.address = pac->address();
            wa.read = make_word(pac->read());
            wa.written = make_word(pac->written());
            std::string note;
            if (has_annotations)
                note = *pnt++;
            if (has_proofs)
                wa.proof = make_proof(pac->proof());
            al.push_access(wa, note.c_str());
            pac++;
            iac++;
        }
    }
    return al;
}

void grpc_virtual_machine::do_shutdown() {
    Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->Shutdown(&context, request, &response));
}

void grpc_virtual_machine::do_snapshot() {
    Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->Snapshot(&context, request, &response));
}

void grpc_virtual_machine::do_rollback() {
    Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->Rollback(&context, request, &response));
}

bool grpc_virtual_machine::do_verify_dirty_page_maps(void) {
    Void request;
    VerifyDirtyPageMapsResponse response;
    ClientContext context;
    check_status(m_stub->VerifyDirtyPageMaps(&context, request, &response));
    return response.success();
}

void grpc_virtual_machine::do_dump_pmas(void) {
    Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->DumpPmas(&context, request, &response));
}

bool grpc_virtual_machine::do_read_word(uint64_t word_address, uint64_t &word_value) {
    ReadWordRequest request;
    request.set_address(word_address);
    ReadWordResponse response;
    ClientContext context;
    check_status(m_stub->ReadWord(&context, request, &response));
    word_value = response.value();
    return response.success();
}

bool grpc_virtual_machine::do_verify_merkle_tree(void) {
    Void request;
    ClientContext context;
    VerifyMerkleTreeResponse response;
    check_status(m_stub->VerifyMerkleTree(&context, request, &response));
    return response.success();
}

bool grpc_virtual_machine::do_update_merkle_tree(void) {
    Void request;
    ClientContext context;
    UpdateMerkleTreeResponse response;
    check_status(m_stub->UpdateMerkleTree(&context, request, &response));
    return response.success();
}



// grpc_virtual_machine::
} // namespace cartesi
