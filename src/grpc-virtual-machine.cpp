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

#include "grpc-util.h"
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
using CartesiMachine::VerifyStateTransitionRequest;
using CartesiMachine::VerifyAccessLogRequest;
using CartesiMachine::MachineConfig;
using CartesiMachine::GetInitialConfigResponse;
using CartesiMachine::GetDefaultConfigResponse;
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
using CartesiMachine::AccessType;
using CartesiMachine::Hash;
using CartesiMachine::GetProofRequest;
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
using Versioning::GetVersionResponse;
using grpc::StatusCode;

using hash_type = cartesi::merkle_tree::hash_type;

namespace cartesi {

static std::string status_code_to_string(StatusCode code) {
    switch (code) {
        case StatusCode::OK: return "ok";
        case StatusCode::CANCELLED: return "cancelled";
        case StatusCode::INVALID_ARGUMENT: return "invalid argument";
        case StatusCode::DEADLINE_EXCEEDED: return "deadline exceeded";
        case StatusCode::NOT_FOUND: return "not found";
        case StatusCode::ALREADY_EXISTS: return "already exists";
        case StatusCode::PERMISSION_DENIED: return "permission denied";
        case StatusCode::UNAUTHENTICATED: return "unauthenticated";
        case StatusCode::RESOURCE_EXHAUSTED: return "resource exhausted";
        case StatusCode::FAILED_PRECONDITION: return "failed precondition";
        case StatusCode::ABORTED: return "aborted";
        case StatusCode::OUT_OF_RANGE: return "out of range";
        case StatusCode::UNIMPLEMENTED: return "unimplemented";
        case StatusCode::INTERNAL: return "internal";
        case StatusCode::UNAVAILABLE: return "unavailable";
        case StatusCode::DATA_LOSS: return "data loss";
        case StatusCode::UNKNOWN: return "unknown";
        default: return "unknown";
    }
}

static void check_status(const Status &status) {
    if (!status.ok()) {
        if (status.error_message().empty()) {
            throw std::runtime_error(status_code_to_string(status.error_code()));
        } else {
            throw std::runtime_error(status.error_message());
        }
    }
}

grpc_virtual_machine::grpc_virtual_machine(grpc_machine_stub_ptr stub,
    const std::string &dir): m_stub(stub) {
    MachineRequest request;
    request.set_directory(dir);
    Void response;
    ClientContext context;
    check_status(m_stub->Machine(&context, request, &response));
}

grpc_virtual_machine::grpc_virtual_machine(grpc_machine_stub_ptr stub,
    const machine_config &c): m_stub(stub) {
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

grpc_virtual_machine::~grpc_virtual_machine(void) {
}

machine_config grpc_virtual_machine::do_get_initial_config(void) {
    Void request;
    GetInitialConfigResponse response;
    ClientContext context;
    check_status(m_stub->GetInitialConfig(&context, request, &response));
    return get_proto_machine_config(response.config());
}

machine_config grpc_virtual_machine::get_default_config(
    grpc_machine_stub_ptr stub) {
    Void request;
    GetDefaultConfigResponse response;
    ClientContext context;
    check_status(stub->GetDefaultConfig(&context, request, &response));
    return get_proto_machine_config(response.config());
}

semantic_version grpc_virtual_machine::get_version(
    grpc_machine_stub_ptr stub) {
    Void request;
    GetVersionResponse response;
    ClientContext context;
    check_status(stub->GetVersion(&context, request, &response));
    return get_proto_semantic_version(response.version());
}

void grpc_virtual_machine::shutdown(grpc_machine_stub_ptr stub) {
    Void request;
    Void response;
    ClientContext context;
    check_status(stub->Shutdown(&context, request, &response));
}

void grpc_virtual_machine::verify_access_log(grpc_machine_stub_ptr stub,
        const access_log &log, bool one_based) {
    VerifyAccessLogRequest request;
    Void response;
    ClientContext context;
    set_proto_access_log(log, request.mutable_log());
    request.set_one_based(one_based);
    check_status(stub->VerifyAccessLog(&context, request, &response));
}

void grpc_virtual_machine::verify_state_transition(grpc_machine_stub_ptr stub,
        const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after, bool one_based) {
    VerifyStateTransitionRequest request;
    Void response;
    ClientContext context;
    set_proto_hash(root_hash_before, request.mutable_root_hash_before());
    set_proto_access_log(log, request.mutable_log());
    set_proto_hash(root_hash_after, request.mutable_root_hash_after());
    request.set_one_based(one_based);
    check_status(stub->VerifyStateTransition(&context, request, &response));
}

grpc_machine_stub_ptr grpc_virtual_machine::stub(
    const std::string &address) {
    return Machine::NewStub(grpc::CreateChannel(address,
            grpc::InsecureChannelCredentials()));
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

uint64_t grpc_virtual_machine::do_read_pc(void) {
    return read_csr(csr::pc);
}

void grpc_virtual_machine::do_write_pc(uint64_t val) {
    write_csr(csr::pc, val);
}

uint64_t grpc_virtual_machine::do_read_mvendorid(void) {
    return read_csr(csr::mvendorid);
}

uint64_t grpc_virtual_machine::do_read_marchid(void) {
    return read_csr(csr::marchid);
}

uint64_t grpc_virtual_machine::do_read_mimpid(void) {
    return read_csr(csr::mimpid);
}

uint64_t grpc_virtual_machine::do_read_mcycle(void) {
    return read_csr(csr::mcycle);
}

void grpc_virtual_machine::do_write_mcycle(uint64_t val) {
    write_csr(csr::mcycle, val);
}

uint64_t grpc_virtual_machine::do_read_minstret(void) {
    return read_csr(csr::minstret);
}

void grpc_virtual_machine::do_write_minstret(uint64_t val) {
    write_csr(csr::minstret, val);
}

uint64_t grpc_virtual_machine::do_read_mstatus(void) {
    return read_csr(csr::mstatus);
}

void grpc_virtual_machine::do_write_mstatus(uint64_t val) {
    write_csr(csr::mstatus, val);
}

uint64_t grpc_virtual_machine::do_read_mtvec(void) {
    return read_csr(csr::mtvec);
}

void grpc_virtual_machine::do_write_mtvec(uint64_t val) {
    write_csr(csr::mtvec, val);
}

uint64_t grpc_virtual_machine::do_read_mscratch(void) {
    return read_csr(csr::mscratch);
}

void grpc_virtual_machine::do_write_mscratch(uint64_t val) {
    write_csr(csr::mscratch, val);
}

uint64_t grpc_virtual_machine::do_read_mepc(void) {
    return read_csr(csr::mepc);
}

void grpc_virtual_machine::do_write_mepc(uint64_t val) {
    write_csr(csr::mepc, val);
}

uint64_t grpc_virtual_machine::do_read_mcause(void) {
    return read_csr(csr::mcause);
}

void grpc_virtual_machine::do_write_mcause(uint64_t val) {
    write_csr(csr::mcause, val);
}

uint64_t grpc_virtual_machine::do_read_mtval(void) {
    return read_csr(csr::mtval);
 }

void grpc_virtual_machine::do_write_mtval(uint64_t val) {
    write_csr(csr::mtval, val);
}

uint64_t grpc_virtual_machine::do_read_misa(void) {
    return read_csr(csr::misa);
}

void grpc_virtual_machine::do_write_misa(uint64_t val) {
    write_csr(csr::misa, val);
}

uint64_t grpc_virtual_machine::do_read_mie(void) {
    return read_csr(csr::mie);
}

void grpc_virtual_machine::do_write_mie(uint64_t val) {
    write_csr(csr::mie, val);
}

uint64_t grpc_virtual_machine::do_read_mip(void) {
    return read_csr(csr::mip);
}

void grpc_virtual_machine::do_write_mip(uint64_t val) {
    write_csr(csr::mip, val);
}

uint64_t grpc_virtual_machine::do_read_medeleg(void) {
    return read_csr(csr::medeleg);
}

void grpc_virtual_machine::do_write_medeleg(uint64_t val) {
    write_csr(csr::medeleg, val);
}

uint64_t grpc_virtual_machine::do_read_mideleg(void) {
    return read_csr(csr::mideleg);
}

void grpc_virtual_machine::do_write_mideleg(uint64_t val) {
    write_csr(csr::mideleg, val);
}

uint64_t grpc_virtual_machine::do_read_mcounteren(void) {
    return read_csr(csr::mcounteren);
}

void grpc_virtual_machine::do_write_mcounteren(uint64_t val) {
    write_csr(csr::mcounteren, val);
}

uint64_t grpc_virtual_machine::do_read_stvec(void) {
    return read_csr(csr::stvec);
}

void grpc_virtual_machine::do_write_stvec(uint64_t val) {
    write_csr(csr::stvec, val);
}

uint64_t grpc_virtual_machine::do_read_sscratch(void) {
    return read_csr(csr::sscratch);
}

void grpc_virtual_machine::do_write_sscratch(uint64_t val) {
    write_csr(csr::sscratch, val);
}

uint64_t grpc_virtual_machine::do_read_sepc(void) {
    return read_csr(csr::sepc);
}

void grpc_virtual_machine::do_write_sepc(uint64_t val) {
    write_csr(csr::sepc, val);
}

uint64_t grpc_virtual_machine::do_read_scause(void) {
    return read_csr(csr::scause);
}

void grpc_virtual_machine::do_write_scause(uint64_t val) {
    write_csr(csr::scause, val);
}

uint64_t grpc_virtual_machine::do_read_stval(void) {
    return read_csr(csr::stval);
}

void grpc_virtual_machine::do_write_stval(uint64_t val) {
    write_csr(csr::stval, val);
}

uint64_t grpc_virtual_machine::do_read_satp(void) {
    return read_csr(csr::satp);
}

void grpc_virtual_machine::do_write_satp(uint64_t val) {
    write_csr(csr::satp, val);
}

uint64_t grpc_virtual_machine::do_read_scounteren(void) {
    return read_csr(csr::scounteren);
}

void grpc_virtual_machine::do_write_scounteren(uint64_t val) {
    write_csr(csr::scounteren, val);
}

uint64_t grpc_virtual_machine::do_read_ilrsc(void) {
    return read_csr(csr::ilrsc);
}

void grpc_virtual_machine::do_write_ilrsc(uint64_t val) {
    write_csr(csr::ilrsc, val);
}

uint64_t grpc_virtual_machine::do_read_iflags(void) {
    return read_csr(csr::iflags);
}

bool grpc_virtual_machine::do_read_iflags_H(void) {
    return (read_csr(csr::iflags) >> IFLAGS_H_SHIFT) & 1;
}

bool grpc_virtual_machine::do_read_iflags_I(void) {
    return (read_csr(csr::iflags) >> IFLAGS_I_SHIFT) & 1;
}

bool grpc_virtual_machine::do_read_iflags_Y(void) {
    return (read_csr(csr::iflags) >> IFLAGS_Y_SHIFT) & 1;
}

void grpc_virtual_machine::do_write_iflags(uint64_t val) {
    write_csr(csr::iflags, val);
}

uint64_t grpc_virtual_machine::do_read_htif_tohost(void) {
    return read_csr(csr::htif_tohost);
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_dev(void) {
    return HTIF_DEV_FIELD(read_htif_tohost());
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_cmd(void) {
    return HTIF_CMD_FIELD(read_htif_tohost());
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_data(void) {
    return HTIF_DATA_FIELD(read_htif_tohost());
}

void grpc_virtual_machine::do_write_htif_tohost(uint64_t val) {
    write_csr(csr::htif_tohost, val);
}

uint64_t grpc_virtual_machine::do_read_htif_fromhost(void) {
    return read_csr(csr::htif_fromhost);
}

void grpc_virtual_machine::do_write_htif_fromhost(uint64_t val) {
    write_csr(csr::htif_fromhost, val);
}

void grpc_virtual_machine::do_write_htif_fromhost_data(uint64_t val) {
    write_htif_fromhost(HTIF_REPLACE_DATA(read_htif_fromhost(), val));
}

uint64_t grpc_virtual_machine::do_read_htif_ihalt(void) {
    return read_csr(csr::htif_ihalt);
}

void grpc_virtual_machine::do_write_htif_ihalt(uint64_t val)  {
    write_csr(csr::htif_ihalt, val);
}

uint64_t grpc_virtual_machine::do_read_htif_iconsole(void) {
    return read_csr(csr::htif_iconsole);
}

void grpc_virtual_machine::do_write_htif_iconsole(uint64_t val) {
    write_csr(csr::htif_iconsole, val);
}

uint64_t grpc_virtual_machine::do_read_htif_iyield(void) {
    return read_csr(csr::htif_iyield);
}

void grpc_virtual_machine::do_write_htif_iyield(uint64_t val)  {
    write_csr(csr::htif_iyield, val);
}

uint64_t grpc_virtual_machine::do_read_clint_mtimecmp(void) {
    return read_csr(csr::clint_mtimecmp);
}

void grpc_virtual_machine::do_write_clint_mtimecmp(uint64_t val) {
    write_csr(csr::clint_mtimecmp, val);
}

void grpc_virtual_machine::do_get_root_hash(hash_type &hash)  {
    GetRootHashResponse response;
    Void request;
    ClientContext context;
    check_status(m_stub->GetRootHash(&context, request, &response));
    hash = get_proto_hash(response.hash());
}

void grpc_virtual_machine::do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof)  {
    GetProofRequest request;
    GetProofResponse response;
    request.set_address(address);
    request.set_log2_size(log2_size);
    ClientContext context;
    check_status(m_stub->GetProof(&context, request, &response));
    proof = get_proto_proof(response.proof());
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

access_log grpc_virtual_machine::do_step(const access_log::type &log_type,
    bool one_based) {
    StepRequest request;
    request.mutable_log_type()->set_proofs(log_type.has_proofs());
    request.mutable_log_type()->set_annotations(log_type.has_annotations());
    request.set_one_based(one_based);
    StepResponse response;
    ClientContext context;
    check_status(m_stub->Step(&context, request, &response));
    return get_proto_access_log(response.log());
}

void grpc_virtual_machine::do_destroy() {
    Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->Destroy(&context, request, &response));
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

} // namespace cartesi
