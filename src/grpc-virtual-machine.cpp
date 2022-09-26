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

#include <algorithm>
#include <cstdint>
#include <string>

#include "grpc-virtual-machine.h"
#include "protobuf-util.h"

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;
using namespace CartesiMachine;
using namespace Versioning;

using hash_type = cartesi::machine_merkle_tree::hash_type;

// Doesn't matter because we are not connected to multiple servers and don't have to distinguish between them
constexpr const char *CHECKIN_SESSION_ID = "grpc_virtual_machine";

namespace cartesi {

/// \brief Converts a gRPC status code to string
/// \param code gRPC status code
/// \return String describing code
static std::string status_code_to_string(StatusCode code) {
    switch (code) {
        case StatusCode::OK:
            return "ok";
        case StatusCode::CANCELLED:
            return "cancelled";
        case StatusCode::INVALID_ARGUMENT:
            return "invalid argument";
        case StatusCode::DEADLINE_EXCEEDED:
            return "deadline exceeded";
        case StatusCode::NOT_FOUND:
            return "not found";
        case StatusCode::ALREADY_EXISTS:
            return "already exists";
        case StatusCode::PERMISSION_DENIED:
            return "permission denied";
        case StatusCode::UNAUTHENTICATED:
            return "unauthenticated";
        case StatusCode::RESOURCE_EXHAUSTED:
            return "resource exhausted";
        case StatusCode::FAILED_PRECONDITION:
            return "failed precondition";
        case StatusCode::ABORTED:
            return "aborted";
        case StatusCode::OUT_OF_RANGE:
            return "out of range";
        case StatusCode::UNIMPLEMENTED:
            return "unimplemented";
        case StatusCode::INTERNAL:
            return "internal";
        case StatusCode::UNAVAILABLE:
            return "unavailable";
        case StatusCode::DATA_LOSS:
            return "data loss";
        case StatusCode::UNKNOWN:
            return "unknown";
        default:
            return "unknown";
    }
}

/// \brief Checks if gRPC status is ok and throw otherwise
/// \param status gRPC status
static void check_status(const Status &status) {
    if (!status.ok()) {
        if (status.error_message().empty()) {
            throw std::runtime_error(status_code_to_string(status.error_code()));
        } else {
            throw std::runtime_error(status.error_message());
        }
    }
}

/// \brief Replaces the port specification (i.e., after ':') in an address with a new port
/// \param address Original address
/// \param port New port
/// \return New address with replaced port
static std::string replace_port(const std::string &address, int port) {
    // Unix address?
    if (address.find("unix:") == 0) {
        return address;
    }
    auto pos = address.find_last_of(':');
    // If already has a port, replace
    if (pos != std::string::npos) {
        return address.substr(0, pos) + ":" + std::to_string(port);
        // Otherwise, concatenate
    } else {
        return address + ":" + std::to_string(port);
    }
}

grpc_machine_stub::grpc_machine_stub(std::string remote_address, std::string checkin_address) :
    m_remote_address(std::move(remote_address)),
    m_checkin_address(std::move(checkin_address)),
    m_stub(Machine::NewStub(grpc::CreateChannel(m_remote_address, grpc::InsecureChannelCredentials()))) {
    if (!m_stub) {
        throw std::runtime_error("unable to create stub");
    }
    grpc::ServerBuilder builder;
    int port = 0;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(m_checkin_address, grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(&m_checkin_async_service);
    m_completion_queue = builder.AddCompletionQueue();
    if (!m_completion_queue) {
        throw std::runtime_error("unable to create completion queue");
    }
    m_checkin_server = builder.BuildAndStart();
    if (!m_checkin_server) {
        throw std::runtime_error("unable to create checkin server");
    }
    m_checkin_address = replace_port(m_checkin_address, port);
}

Machine::Stub *grpc_machine_stub::get_stub(void) {
    return m_stub.get();
}

const Machine::Stub *grpc_machine_stub::get_stub(void) const {
    return m_stub.get();
}

const std::string &grpc_machine_stub::get_remote_address(void) const {
    return m_remote_address;
}

const std::string &grpc_machine_stub::get_checkin_address(void) const {
    return m_checkin_address;
}

/// \brief Returns a time in the future
/// \param sec Amount of seconds in the future
/// \return Time
static auto time_in_future(int sec) {
    return gpr_time_add(gpr_now(gpr_clock_type::GPR_CLOCK_REALTIME),
        gpr_time_from_seconds(sec, gpr_clock_type::GPR_TIMESPAN));
}

void grpc_machine_stub::prepare_checkin(void) {
    // Inform remote server of checkin target
    // ??D no need to do this every time, but no harm either
    SetCheckInTargetRequest request;
    Void response;
    ClientContext context;
    request.set_session_id(CHECKIN_SESSION_ID);
    request.set_address(m_checkin_address);
    check_status(m_stub->SetCheckInTarget(&context, request, &response));
    // Destroy old and create new server context and writer for the async checkin handler
    m_checkin_context.reset();
    m_checkin_context.emplace();
    auto &ctx = m_checkin_context.value();
    // Install the checkin handler
    auto *cq = m_completion_queue.get();
    m_checkin_async_service.RequestCheckIn(&ctx.server_context, &ctx.request, &ctx.writer, cq, cq, this);
}

void grpc_machine_stub::wait_checkin_and_reconnect(void) {
    if (!m_checkin_context.has_value()) { // NOLINT: grpc warnings
        throw std::runtime_error("missing call to prepare checkin");
    }
    auto &ctx = m_checkin_context.value();
    // Wait for checkin rpc
    bool ok = false;
    void *tag = nullptr;
    if (m_completion_queue->AsyncNext(&tag, &ok, time_in_future(5)) != grpc::CompletionQueue::NextStatus::GOT_EVENT) {
        throw std::runtime_error("gave up waiting for checkin request");
    }
    if (ctx.request.session_id() != CHECKIN_SESSION_ID) {
        throw std::runtime_error("expected '" + std::string(CHECKIN_SESSION_ID) + "' checkin session id (got '" +
            ctx.request.session_id() + "')");
    }
    if (tag != this) {
        throw std::runtime_error("unexpected checkin tag");
    }
    m_remote_address = ctx.request.address();
    // Acknowledge rpc
    ok = false;
    tag = nullptr;
    const Void response;
    ctx.writer.Finish(response, grpc::Status::OK, this); // NOLINT: grpc warnings
    if (m_completion_queue->AsyncNext(&tag, &ok, time_in_future(5)) != grpc::CompletionQueue::NextStatus::GOT_EVENT) {
        throw std::runtime_error("gave up waiting for checkin response");
    }
    // Reconnect
    m_stub = Machine::NewStub(grpc::CreateChannel(m_remote_address, grpc::InsecureChannelCredentials()));
    if (!m_stub) {
        throw std::runtime_error("unable to create stub");
    }
}

grpc_machine_stub::~grpc_machine_stub() {
    m_checkin_server->Shutdown();
    // drain completion queue
    auto *cq = m_completion_queue.get();
    cq->Shutdown();
    bool ok = false;
    void *tag = nullptr;
    while (cq->Next(&tag, &ok)) {
        ;
    }
}

grpc_virtual_machine::grpc_virtual_machine(grpc_machine_stub_ptr stub) : m_stub(std::move(stub)) {}

grpc_virtual_machine::grpc_virtual_machine(grpc_machine_stub_ptr stub, const std::string &dir,
    const machine_runtime_config &r) :
    m_stub(std::move(stub)) {
    MachineRequest request;
    request.set_directory(dir);
    set_proto_machine_runtime_config(r, request.mutable_runtime());
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->Machine(&context, request, &response));
}

grpc_virtual_machine::grpc_virtual_machine(grpc_machine_stub_ptr stub, const machine_config &c,
    const machine_runtime_config &r) :
    m_stub(std::move(stub)) {
    MachineRequest request;
    set_proto_machine_config(c, request.mutable_config());
    set_proto_machine_runtime_config(r, request.mutable_runtime());
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->Machine(&context, request, &response));
}

grpc_virtual_machine::~grpc_virtual_machine(void) = default;

machine_config grpc_virtual_machine::do_get_initial_config(void) const {
    const Void request;
    GetInitialConfigResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->GetInitialConfig(&context, request, &response));
    return get_proto_machine_config(response.config());
}

machine_config grpc_virtual_machine::get_default_config(const grpc_machine_stub_ptr &stub) {
    const Void request;
    GetDefaultConfigResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetDefaultConfig(&context, request, &response));
    return get_proto_machine_config(response.config());
}

semantic_version grpc_virtual_machine::get_version(const grpc_machine_stub_ptr &stub) {
    const Void request;
    GetVersionResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetVersion(&context, request, &response));
    return get_proto_semantic_version(response.version());
}

void grpc_virtual_machine::shutdown(const grpc_machine_stub_ptr &stub) {
    const Void request;
    Void response;
    ClientContext context;
    check_status(stub->get_stub()->Shutdown(&context, request, &response));
}

void grpc_virtual_machine::verify_access_log(const grpc_machine_stub_ptr &stub, const access_log &log,
    const machine_runtime_config &r, bool one_based) {
    VerifyAccessLogRequest request;
    Void response;
    ClientContext context;
    set_proto_access_log(log, request.mutable_log());
    set_proto_machine_runtime_config(r, request.mutable_runtime());
    request.set_one_based(one_based);
    check_status(stub->get_stub()->VerifyAccessLog(&context, request, &response));
}

void grpc_virtual_machine::verify_state_transition(const grpc_machine_stub_ptr &stub, const hash_type &root_hash_before,
    const access_log &log, const hash_type &root_hash_after, const machine_runtime_config &r, bool one_based) {
    VerifyStateTransitionRequest request;
    Void response;
    ClientContext context;
    set_proto_hash(root_hash_before, request.mutable_root_hash_before());
    set_proto_access_log(log, request.mutable_log());
    set_proto_hash(root_hash_after, request.mutable_root_hash_after());
    set_proto_machine_runtime_config(r, request.mutable_runtime());
    request.set_one_based(one_based);
    check_status(stub->get_stub()->VerifyStateTransition(&context, request, &response));
}

interpreter_break_reason grpc_virtual_machine::do_run(uint64_t mcycle_end) {
    RunRequest request;
    request.set_limit(mcycle_end);
    RunResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->Run(&context, request, &response));
    if (response.iflags_h()) {
        return interpreter_break_reason::halted;
    } else if (response.iflags_y()) {
        return interpreter_break_reason::yielded_manually;
    } else if (response.iflags_x()) {
        return interpreter_break_reason::yielded_automatically;
    } else {
        assert(response.mcycle() == mcycle_end);
        return interpreter_break_reason::reached_target_mcycle;
    }
}

void grpc_virtual_machine::do_store(const std::string &dir) {
    StoreRequest request;
    request.set_directory(dir);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->Store(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_read_csr(csr r) const {
    ReadCsrRequest request;
    static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
    request.set_csr(static_cast<Csr>(r));
    ReadCsrResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadCsr(&context, request, &response));
    return response.value();
}

void grpc_virtual_machine::do_write_csr(csr w, uint64_t val) {
    WriteCsrRequest request;
    static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
    request.set_csr(static_cast<Csr>(w));
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->WriteCsr(&context, request, &response));
}

uint64_t grpc_virtual_machine::get_csr_address(const grpc_machine_stub_ptr &stub, csr w) {
    GetCsrAddressRequest request;
    static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
    request.set_csr(static_cast<Csr>(w));
    GetCsrAddressResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetCsrAddress(&context, request, &response));
    return response.address();
}

uint64_t grpc_virtual_machine::do_read_x(int i) const {
    ReadXRequest request;
    request.set_index(i);
    ReadXResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadX(&context, request, &response));
    return response.value();
}

void grpc_virtual_machine::do_write_x(int i, uint64_t val) {
    WriteXRequest request;
    request.set_index(i);
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->WriteX(&context, request, &response));
}

uint64_t grpc_virtual_machine::get_x_address(const grpc_machine_stub_ptr &stub, int i) {
    GetXAddressRequest request;
    request.set_index(i);
    GetXAddressResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetXAddress(&context, request, &response));
    return response.address();
}

uint64_t grpc_virtual_machine::do_read_f(int i) const {
    ReadFRequest request;
    request.set_index(i);
    ReadFResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadF(&context, request, &response));
    return response.value();
}

void grpc_virtual_machine::do_write_f(int i, uint64_t val) {
    WriteFRequest request;
    request.set_index(i);
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->WriteF(&context, request, &response));
}

uint64_t grpc_virtual_machine::get_f_address(const grpc_machine_stub_ptr &stub, int i) {
    GetFAddressRequest request;
    request.set_index(i);
    GetFAddressResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetFAddress(&context, request, &response));
    return response.address();
}

void grpc_virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    ReadMemoryRequest request;
    request.set_address(address);
    request.set_length(length);
    ReadMemoryResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadMemory(&context, request, &response));
    assert(response.data().size() == length);
    memcpy(data, response.data().data(), length);
}

void grpc_virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, size_t length) {
    WriteMemoryRequest request;
    request.set_address(address);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    request.set_data(std::string(reinterpret_cast<const char *>(data), length));
    ClientContext context;
    Void response;
    check_status(m_stub->get_stub()->WriteMemory(&context, request, &response));
}

void grpc_virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    ReadMemoryRequest request;
    request.set_address(address);
    request.set_length(length);
    ReadMemoryResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadVirtualMemory(&context, request, &response));
    assert(response.data().size() == length);
    memcpy(data, response.data().data(), length);
}

void grpc_virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) {
    WriteMemoryRequest request;
    request.set_address(address);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    request.set_data(std::string(reinterpret_cast<const char *>(data), length));
    ClientContext context;
    Void response;
    check_status(m_stub->get_stub()->WriteVirtualMemory(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_read_pc(void) const {
    return read_csr(csr::pc);
}

void grpc_virtual_machine::do_write_pc(uint64_t val) {
    write_csr(csr::pc, val);
}

uint64_t grpc_virtual_machine::do_read_fcsr(void) const {
    return read_csr(csr::fcsr);
}

void grpc_virtual_machine::do_write_fcsr(uint64_t val) {
    write_csr(csr::fcsr, val);
}

uint64_t grpc_virtual_machine::do_read_mvendorid(void) const {
    return read_csr(csr::mvendorid);
}

uint64_t grpc_virtual_machine::do_read_marchid(void) const {
    return read_csr(csr::marchid);
}

uint64_t grpc_virtual_machine::do_read_mimpid(void) const {
    return read_csr(csr::mimpid);
}

uint64_t grpc_virtual_machine::do_read_mcycle(void) const {
    return read_csr(csr::mcycle);
}

void grpc_virtual_machine::do_write_mcycle(uint64_t val) {
    write_csr(csr::mcycle, val);
}

uint64_t grpc_virtual_machine::do_read_icycleinstret(void) const {
    return read_csr(csr::icycleinstret);
}

void grpc_virtual_machine::do_write_icycleinstret(uint64_t val) {
    write_csr(csr::icycleinstret, val);
}

uint64_t grpc_virtual_machine::do_read_mstatus(void) const {
    return read_csr(csr::mstatus);
}

void grpc_virtual_machine::do_write_mstatus(uint64_t val) {
    write_csr(csr::mstatus, val);
}

uint64_t grpc_virtual_machine::do_read_mtvec(void) const {
    return read_csr(csr::mtvec);
}

void grpc_virtual_machine::do_write_mtvec(uint64_t val) {
    write_csr(csr::mtvec, val);
}

uint64_t grpc_virtual_machine::do_read_mscratch(void) const {
    return read_csr(csr::mscratch);
}

void grpc_virtual_machine::do_write_mscratch(uint64_t val) {
    write_csr(csr::mscratch, val);
}

uint64_t grpc_virtual_machine::do_read_mepc(void) const {
    return read_csr(csr::mepc);
}

void grpc_virtual_machine::do_write_mepc(uint64_t val) {
    write_csr(csr::mepc, val);
}

uint64_t grpc_virtual_machine::do_read_mcause(void) const {
    return read_csr(csr::mcause);
}

void grpc_virtual_machine::do_write_mcause(uint64_t val) {
    write_csr(csr::mcause, val);
}

uint64_t grpc_virtual_machine::do_read_mtval(void) const {
    return read_csr(csr::mtval);
}

void grpc_virtual_machine::do_write_mtval(uint64_t val) {
    write_csr(csr::mtval, val);
}

uint64_t grpc_virtual_machine::do_read_misa(void) const {
    return read_csr(csr::misa);
}

void grpc_virtual_machine::do_write_misa(uint64_t val) {
    write_csr(csr::misa, val);
}

uint64_t grpc_virtual_machine::do_read_mie(void) const {
    return read_csr(csr::mie);
}

void grpc_virtual_machine::do_write_mie(uint64_t val) {
    write_csr(csr::mie, val);
}

uint64_t grpc_virtual_machine::do_read_mip(void) const {
    return read_csr(csr::mip);
}

void grpc_virtual_machine::do_write_mip(uint64_t val) {
    write_csr(csr::mip, val);
}

uint64_t grpc_virtual_machine::do_read_medeleg(void) const {
    return read_csr(csr::medeleg);
}

void grpc_virtual_machine::do_write_medeleg(uint64_t val) {
    write_csr(csr::medeleg, val);
}

uint64_t grpc_virtual_machine::do_read_mideleg(void) const {
    return read_csr(csr::mideleg);
}

void grpc_virtual_machine::do_write_mideleg(uint64_t val) {
    write_csr(csr::mideleg, val);
}

uint64_t grpc_virtual_machine::do_read_mcounteren(void) const {
    return read_csr(csr::mcounteren);
}

void grpc_virtual_machine::do_write_mcounteren(uint64_t val) {
    write_csr(csr::mcounteren, val);
}

uint64_t grpc_virtual_machine::do_read_menvcfg(void) const {
    return read_csr(csr::menvcfg);
}

void grpc_virtual_machine::do_write_menvcfg(uint64_t val) {
    write_csr(csr::menvcfg, val);
}

uint64_t grpc_virtual_machine::do_read_stvec(void) const {
    return read_csr(csr::stvec);
}

void grpc_virtual_machine::do_write_stvec(uint64_t val) {
    write_csr(csr::stvec, val);
}

uint64_t grpc_virtual_machine::do_read_sscratch(void) const {
    return read_csr(csr::sscratch);
}

void grpc_virtual_machine::do_write_sscratch(uint64_t val) {
    write_csr(csr::sscratch, val);
}

uint64_t grpc_virtual_machine::do_read_sepc(void) const {
    return read_csr(csr::sepc);
}

void grpc_virtual_machine::do_write_sepc(uint64_t val) {
    write_csr(csr::sepc, val);
}

uint64_t grpc_virtual_machine::do_read_scause(void) const {
    return read_csr(csr::scause);
}

void grpc_virtual_machine::do_write_scause(uint64_t val) {
    write_csr(csr::scause, val);
}

uint64_t grpc_virtual_machine::do_read_stval(void) const {
    return read_csr(csr::stval);
}

void grpc_virtual_machine::do_write_stval(uint64_t val) {
    write_csr(csr::stval, val);
}

uint64_t grpc_virtual_machine::do_read_satp(void) const {
    return read_csr(csr::satp);
}

void grpc_virtual_machine::do_write_satp(uint64_t val) {
    write_csr(csr::satp, val);
}

uint64_t grpc_virtual_machine::do_read_scounteren(void) const {
    return read_csr(csr::scounteren);
}

void grpc_virtual_machine::do_write_scounteren(uint64_t val) {
    write_csr(csr::scounteren, val);
}

uint64_t grpc_virtual_machine::do_read_senvcfg(void) const {
    return read_csr(csr::senvcfg);
}

void grpc_virtual_machine::do_write_senvcfg(uint64_t val) {
    write_csr(csr::senvcfg, val);
}

uint64_t grpc_virtual_machine::do_read_hstatus(void) const {
    return read_csr(csr::hstatus);
}

void grpc_virtual_machine::do_write_hstatus(uint64_t val) {
    write_csr(csr::hstatus, val);
}

uint64_t grpc_virtual_machine::do_read_hideleg(void) const {
    return read_csr(csr::hideleg);
}

void grpc_virtual_machine::do_write_hideleg(uint64_t val) {
    write_csr(csr::hideleg, val);
}

uint64_t grpc_virtual_machine::do_read_hedeleg(void) const {
    return read_csr(csr::hedeleg);
}

void grpc_virtual_machine::do_write_hedeleg(uint64_t val) {
    write_csr(csr::hedeleg, val);
}

uint64_t grpc_virtual_machine::do_read_hip(void) const {
    return read_csr(csr::hip);
}

void grpc_virtual_machine::do_write_hip(uint64_t val) {
    write_csr(csr::hip, val);
}

uint64_t grpc_virtual_machine::do_read_hvip(void) const {
    return read_csr(csr::hvip);
}

void grpc_virtual_machine::do_write_hvip(uint64_t val) {
    write_csr(csr::hvip, val);
}

uint64_t grpc_virtual_machine::do_read_hie(void) const {
    return read_csr(csr::hie);
}

void grpc_virtual_machine::do_write_hie(uint64_t val) {
    write_csr(csr::hie, val);
}

uint64_t grpc_virtual_machine::do_read_hgatp(void) const {
    return read_csr(csr::hgatp);
}

void grpc_virtual_machine::do_write_hgatp(uint64_t val) {
    write_csr(csr::hgatp, val);
}

uint64_t grpc_virtual_machine::do_read_henvcfg(void) const {
    return read_csr(csr::henvcfg);
}

void grpc_virtual_machine::do_write_henvcfg(uint64_t val) {
    write_csr(csr::henvcfg, val);
}

uint64_t grpc_virtual_machine::do_read_htimedelta(void) const {
    return read_csr(csr::htimedelta);
}

void grpc_virtual_machine::do_write_htimedelta(uint64_t val) {
    write_csr(csr::htimedelta, val);
}

uint64_t grpc_virtual_machine::do_read_htval(void) const {
    return read_csr(csr::htval);
}

void grpc_virtual_machine::do_write_htval(uint64_t val) {
    write_csr(csr::htval, val);
}

uint64_t grpc_virtual_machine::do_read_vsepc(void) const {
    return read_csr(csr::vsepc);
}

void grpc_virtual_machine::do_write_vsepc(uint64_t val) {
    write_csr(csr::vsepc, val);
}

uint64_t grpc_virtual_machine::do_read_vsstatus(void) const {
    return read_csr(csr::vsstatus);
}

void grpc_virtual_machine::do_write_vsstatus(uint64_t val) {
    write_csr(csr::vsstatus, val);
}

uint64_t grpc_virtual_machine::do_read_vscause(void) const {
    return read_csr(csr::vscause);
}

void grpc_virtual_machine::do_write_vscause(uint64_t val) {
    write_csr(csr::vscause, val);
}

uint64_t grpc_virtual_machine::do_read_vstval(void) const {
    return read_csr(csr::vstval);
}

void grpc_virtual_machine::do_write_vstval(uint64_t val) {
    write_csr(csr::vstval, val);
}

uint64_t grpc_virtual_machine::do_read_vstvec(void) const {
    return read_csr(csr::vstvec);
}

void grpc_virtual_machine::do_write_vstvec(uint64_t val) {
    write_csr(csr::vstvec, val);
}

uint64_t grpc_virtual_machine::do_read_vsscratch(void) const {
    return read_csr(csr::vsscratch);
}

void grpc_virtual_machine::do_write_vsscratch(uint64_t val) {
    write_csr(csr::vsscratch, val);
}

uint64_t grpc_virtual_machine::do_read_vsatp(void) const {
    return read_csr(csr::vsatp);
}

void grpc_virtual_machine::do_write_vsatp(uint64_t val) {
    write_csr(csr::vsatp, val);
}

uint64_t grpc_virtual_machine::do_read_vsip(void) const {
    return read_csr(csr::vsip);
}

void grpc_virtual_machine::do_write_vsip(uint64_t val) {
    write_csr(csr::vsip, val);
}

uint64_t grpc_virtual_machine::do_read_vsie(void) const {
    return read_csr(csr::vsie);
}

void grpc_virtual_machine::do_write_vsie(uint64_t val) {
    write_csr(csr::vsie, val);
}

uint64_t grpc_virtual_machine::do_read_ilrsc(void) const {
    return read_csr(csr::ilrsc);
}

void grpc_virtual_machine::do_write_ilrsc(uint64_t val) {
    write_csr(csr::ilrsc, val);
}

uint64_t grpc_virtual_machine::do_read_iflags(void) const {
    return read_csr(csr::iflags);
}

bool grpc_virtual_machine::do_read_iflags_H(void) const {
    return (read_csr(csr::iflags) >> IFLAGS_H_SHIFT) & 1;
}

bool grpc_virtual_machine::do_read_iflags_Y(void) const {
    return (read_csr(csr::iflags) >> IFLAGS_Y_SHIFT) & 1;
}

bool grpc_virtual_machine::do_read_iflags_X(void) const {
    return (read_csr(csr::iflags) >> IFLAGS_X_SHIFT) & 1;
}

void grpc_virtual_machine::do_set_iflags_H(void) {
    return write_csr(csr::iflags, read_csr(csr::iflags) | IFLAGS_H_MASK);
}

void grpc_virtual_machine::do_set_iflags_Y(void) {
    return write_csr(csr::iflags, read_csr(csr::iflags) | IFLAGS_Y_MASK);
}

void grpc_virtual_machine::do_set_iflags_X(void) {
    return write_csr(csr::iflags, read_csr(csr::iflags) | IFLAGS_X_MASK);
}

void grpc_virtual_machine::do_reset_iflags_Y(void) {
    const Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->ResetIflagsY(&context, request, &response));
}

void grpc_virtual_machine::do_reset_iflags_X(void) {
    return write_csr(csr::iflags, read_csr(csr::iflags) & (~IFLAGS_X_MASK));
}

void grpc_virtual_machine::do_write_iflags(uint64_t val) {
    write_csr(csr::iflags, val);
}

uint64_t grpc_virtual_machine::do_read_htif_tohost(void) const {
    return read_csr(csr::htif_tohost);
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_dev(void) const {
    return HTIF_DEV_FIELD(read_htif_tohost());
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_cmd(void) const {
    return HTIF_CMD_FIELD(read_htif_tohost());
}

uint64_t grpc_virtual_machine::do_read_htif_tohost_data(void) const {
    return HTIF_DATA_FIELD(read_htif_tohost());
}

void grpc_virtual_machine::do_write_htif_tohost(uint64_t val) {
    write_csr(csr::htif_tohost, val);
}

uint64_t grpc_virtual_machine::do_read_htif_fromhost(void) const {
    return read_csr(csr::htif_fromhost);
}

void grpc_virtual_machine::do_write_htif_fromhost(uint64_t val) {
    write_csr(csr::htif_fromhost, val);
}

void grpc_virtual_machine::do_write_htif_fromhost_data(uint64_t val) {
    write_htif_fromhost(HTIF_REPLACE_DATA(read_htif_fromhost(), val));
}

uint64_t grpc_virtual_machine::do_read_htif_ihalt(void) const {
    return read_csr(csr::htif_ihalt);
}

void grpc_virtual_machine::do_write_htif_ihalt(uint64_t val) {
    write_csr(csr::htif_ihalt, val);
}

uint64_t grpc_virtual_machine::do_read_htif_iconsole(void) const {
    return read_csr(csr::htif_iconsole);
}

void grpc_virtual_machine::do_write_htif_iconsole(uint64_t val) {
    write_csr(csr::htif_iconsole, val);
}

uint64_t grpc_virtual_machine::do_read_htif_iyield(void) const {
    return read_csr(csr::htif_iyield);
}

void grpc_virtual_machine::do_write_htif_iyield(uint64_t val) {
    write_csr(csr::htif_iyield, val);
}

uint64_t grpc_virtual_machine::do_read_clint_mtimecmp(void) const {
    return read_csr(csr::clint_mtimecmp);
}

void grpc_virtual_machine::do_write_clint_mtimecmp(uint64_t val) {
    write_csr(csr::clint_mtimecmp, val);
}

void grpc_virtual_machine::do_get_root_hash(hash_type &hash) const {
    GetRootHashResponse response;
    const Void request;
    ClientContext context;
    check_status(m_stub->get_stub()->GetRootHash(&context, request, &response));
    hash = get_proto_hash(response.hash());
}

machine_merkle_tree::proof_type grpc_virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    GetProofRequest request;
    GetProofResponse response;
    request.set_address(address);
    request.set_log2_size(log2_size);
    ClientContext context;
    check_status(m_stub->get_stub()->GetProof(&context, request, &response));
    return get_proto_merkle_tree_proof(response.proof());
}

void grpc_virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    ReplaceMemoryRangeRequest request;
    MemoryRangeConfig *range = request.mutable_config();
    range->set_start(new_range.start);
    range->set_length(new_range.length);
    range->set_shared(new_range.shared);
    range->set_image_filename(new_range.image_filename);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReplaceMemoryRange(&context, request, &response));
}

access_log grpc_virtual_machine::do_step_uarch(const access_log::type &log_type, bool one_based) {
    StepUarchRequest request;
    request.mutable_log_type()->set_proofs(log_type.has_proofs());
    request.mutable_log_type()->set_annotations(log_type.has_annotations());
    request.set_one_based(one_based);
    StepUarchResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->StepUarch(&context, request, &response));
    return get_proto_access_log(response.log());
}

void grpc_virtual_machine::do_destroy() {
    const Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->Destroy(&context, request, &response));
}

void grpc_virtual_machine::do_snapshot() {
    const Void request;
    Void response;
    ClientContext context;
    m_stub->prepare_checkin();
    check_status(m_stub->get_stub()->Snapshot(&context, request, &response));
    m_stub->wait_checkin_and_reconnect();
}

void grpc_virtual_machine::do_rollback() {
    const Void request;
    Void response;
    ClientContext context;
    m_stub->prepare_checkin();
    check_status(m_stub->get_stub()->Rollback(&context, request, &response));
    m_stub->wait_checkin_and_reconnect();
}

bool grpc_virtual_machine::do_verify_dirty_page_maps(void) const {
    const Void request;
    VerifyDirtyPageMapsResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->VerifyDirtyPageMaps(&context, request, &response));
    return response.success();
}

void grpc_virtual_machine::do_dump_pmas(void) const {
    const Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->DumpPmas(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_read_word(uint64_t address) const {
    ReadWordRequest request;
    request.set_address(address);
    ReadWordResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadWord(&context, request, &response));
    return response.value();
}

bool grpc_virtual_machine::do_verify_merkle_tree(void) const {
    const Void request;
    ClientContext context;
    VerifyMerkleTreeResponse response;
    check_status(m_stub->get_stub()->VerifyMerkleTree(&context, request, &response));
    return response.success();
}

uint64_t grpc_virtual_machine::get_uarch_x_address(const grpc_machine_stub_ptr &stub, int i) {
    GetUarchXAddressRequest request;
    request.set_index(i);
    GetUarchXAddressResponse response;
    ClientContext context;
    check_status(stub->get_stub()->GetUarchXAddress(&context, request, &response));
    return response.address();
}

uint64_t grpc_virtual_machine::do_read_uarch_x(int i) const {
    ReadUarchXRequest request;
    request.set_index(i);
    ReadUarchXResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->ReadUarchX(&context, request, &response));
    return response.value();
}

void grpc_virtual_machine::do_write_uarch_x(int i, uint64_t val) {
    WriteUarchXRequest request;
    request.set_index(i);
    request.set_value(val);
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->WriteUarchX(&context, request, &response));
}

uint64_t grpc_virtual_machine::do_read_uarch_pc(void) const {
    return read_csr(csr::uarch_pc);
}

void grpc_virtual_machine::do_write_uarch_pc(uint64_t val) {
    write_csr(csr::uarch_pc, val);
}

uint64_t grpc_virtual_machine::do_read_uarch_cycle(void) const {
    return read_csr(csr::uarch_cycle);
}

void grpc_virtual_machine::do_write_uarch_cycle(uint64_t val) {
    write_csr(csr::uarch_cycle, val);
}

void grpc_virtual_machine::do_set_uarch_halt_flag() {
    write_csr(csr::uarch_halt_flag, true);
}

void grpc_virtual_machine::do_reset_uarch_state() {
    const Void request;
    Void response;
    ClientContext context;
    check_status(m_stub->get_stub()->ResetUarchState(&context, request, &response));
}

bool grpc_virtual_machine::do_read_uarch_halt_flag(void) const {
    return read_csr(csr::uarch_halt_flag);
}

uint64_t grpc_virtual_machine::do_read_uarch_ram_length(void) const {
    return read_csr(csr::uarch_ram_length);
}

uarch_interpreter_break_reason grpc_virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    RunUarchRequest request;
    request.set_limit(uarch_cycle_end);
    RunUarchResponse response;
    ClientContext context;
    check_status(m_stub->get_stub()->RunUarch(&context, request, &response));
    if (response.halt_flag()) {
        return uarch_interpreter_break_reason::uarch_halted;
    }
    return uarch_interpreter_break_reason::reached_target_cycle;
}

} // namespace cartesi
