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

#include <csignal>
#include <cstdint>
#include <exception>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <typeinfo>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include <boost/core/demangle.hpp>

#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>

#include "cartesi-machine-checkin.grpc.pb.h"
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

#include "machine.h"
#include "protobuf-util.h"
#include "unique-c-ptr.h"
#define SLOG_PREFIX log_prefix
#include "slog.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PROGRAM_NAME "remote-cartesi-machine"

using namespace cartesi;
using hash_type = keccak_256_hasher::hash_type;
using namespace CartesiMachine;
using namespace Versioning;
using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
// NOLINTNEXTLINE(misc-unused-using-decls)
using std::chrono_literals::operator""ms;

/// \brief Type for printing time, log severity level, program name, pid, and ppid prefix to each log line
struct log_prefix {
    slog::severity_level level;
};

/// \brief Stream-out operator for log prefix class
std::ostream &operator<<(std::ostream &out, log_prefix prefix) {
    using namespace slog;
    char stime[std::size("yyyy-mm-dd hh-mm-ss")];
    time_t t = time(nullptr);
    struct tm ttime {};
    if (strftime(std::data(stime), std::size(stime), "%Y-%m-%d %H-%M-%S", localtime_r(&t, &ttime))) {
        out << stime << " ";
    }
    out << to_string(prefix.level) << " ";
    out << PROGRAM_NAME << " ";
    out << "pid:" << getpid() << " ";
    out << "ppid:" << getppid() << " ";
    return out;
}

static constexpr uint32_t server_version_major = 0;
static constexpr uint32_t server_version_minor = 7;
static constexpr uint32_t server_version_patch = 0;
static constexpr const char *server_version_pre_release = "";
static constexpr const char *server_version_build = "";

// Check-in deadline/timeout in milliseconds
static constexpr uint64_t checkin_deadline = 5000;
// Check-in max number of retry attempts
static constexpr uint64_t checkin_retry_attempts = 3;
// Check-in retry wait time before next attempt
static constexpr std::chrono::milliseconds checkin_retry_wait_time = 500ms;

static std::string message_to_json(const google::protobuf::Message &msg) {
    std::string json_msg;
    google::protobuf::util::JsonOptions json_opts;
    google::protobuf::util::Status s = MessageToJsonString(msg, &json_msg, json_opts);
    if (s.ok()) {
        return json_msg;
    }
    return "[grpc message decoding failed]";
}

struct checkin_context {
    checkin_context(const char *session_id, const char *checkin_address) :
        session_id(session_id),
        checkin_address(checkin_address) {}
    checkin_context(std::string session_id, std::string checkin_address) :
        session_id(std::move(session_id)),
        checkin_address(std::move(checkin_address)) {}
    std::string session_id;
    std::string checkin_address;
};

struct handler_context {
    std::unique_ptr<machine> m;
    std::unique_ptr<Machine::AsyncService> s;
    std::unique_ptr<ServerCompletionQueue> cq;
    std::optional<checkin_context> checkin;
    bool ok;
    bool forked;
};

class i_handler {
public:
    enum class side_effect { none, snapshot, rollback, shutdown };

    side_effect advance(handler_context &hctx) {
        return do_advance(hctx);
    }

    i_handler() = default;
    virtual ~i_handler() = default;
    i_handler(const i_handler &other) = delete;
    i_handler(i_handler &&other) noexcept = delete;
    i_handler &operator=(const i_handler &other) = delete;
    i_handler &operator=(i_handler &&other) noexcept = delete;

private:
    virtual side_effect do_advance(handler_context &hctx) = 0;
};

template <typename REQUEST, typename RESPONSE>
class handler : public i_handler {

    using sctx = ServerContext;
    using writer = ServerAsyncResponseWriter<RESPONSE>;

    writer m_writer;
    bool m_waiting;

    REQUEST m_request;
    sctx m_sctx;

    void renew_ctx(void) {
        m_writer.~writer();
        m_sctx.~sctx();
        new (&m_sctx) sctx();
        new (&m_writer) writer(&m_sctx);
    }

    side_effect do_advance(handler_context &hctx) override {
        if (m_waiting) {
            m_waiting = false;
            if (hctx.ok) {
                try {
                    SLOG(debug) << "Executing " << boost::core::demangle(typeid(*this).name()) << " go method";
                    SLOG(trace) << "Received request was: " << message_to_json(m_request);
                    return go(hctx, &m_request, &m_writer);
                } catch (std::exception &e) {
                    return finish_with_exception(&m_writer, e);
                }
            }
            return side_effect::none;
        } else {
            renew_ctx();
            m_waiting = true;
            SLOG(trace) << "Executing " << boost::core::demangle(typeid(*this).name()) << " prepare method";
            return prepare(hctx, &m_sctx, &m_request, &m_writer);
        }
    }

    virtual side_effect prepare(handler_context &hctx, ServerContext *sctx, REQUEST *req,
        ServerAsyncResponseWriter<RESPONSE> *writer) = 0;

    virtual side_effect go(handler_context &hctx, REQUEST *req, ServerAsyncResponseWriter<RESPONSE> *writer) = 0;

protected:
    side_effect finish_ok(ServerAsyncResponseWriter<RESPONSE> *writer, const RESPONSE &resp,
        side_effect se = side_effect::none) {
        SLOG(debug) << boost::core::demangle(typeid(*this).name()) << " finish_ok";
        SLOG(trace) << "Response is: " << message_to_json(resp);
        writer->Finish(resp, Status::OK, this); // NOLINT: suppress warning caused by gRPC
        return se;
    }

    side_effect finish_with_error(ServerAsyncResponseWriter<RESPONSE> *writer, StatusCode sc, const char *e,
        side_effect se = side_effect::none) {
        SLOG(error) << boost::core::demangle(typeid(*this).name()) << " finish_with_error: " << e
                    << " StatusCode: " << sc << " side_effect: " << static_cast<unsigned int>(se);
        writer->FinishWithError(Status(sc, e), this);
        return se;
    }

    side_effect finish_with_exception(ServerAsyncResponseWriter<RESPONSE> *writer, const std::exception &e,
        side_effect se = side_effect::none) {
        SLOG(debug) << boost::core::demangle(typeid(*this).name()) << " finish_with_exception";
        return finish_with_error(writer, StatusCode::ABORTED, e.what(), se);
    }

    side_effect finish_with_error_no_machine(ServerAsyncResponseWriter<RESPONSE> *writer) {
        SLOG(debug) << boost::core::demangle(typeid(*this).name()) << " finish_with_error_no_machine";
        return finish_with_error(writer, StatusCode::FAILED_PRECONDITION, "no machine", side_effect::none);
    }

public:
    ~handler() override = default;
    handler(const handler &other) = delete;
    handler(handler &&other) noexcept = delete;
    handler &operator=(const handler &other) = delete;
    handler &operator=(handler &&other) noexcept = delete;

    handler(void) : m_writer(&m_sctx), m_waiting(false) {
        ;
    }
};

static void squash_parent(bool &forked) {
    SLOG(trace) << "squash_parent called with forked: " << forked;
    // If we are a forked child, we have a parent waiting.
    // We want to take its place before exiting.
    // Wake parent up by signaling ourselves to stop.
    // Parent will wake us back up and then exit.
    if (forked) {
        SLOG(trace) << "rasing SIGSTOP";
        int result = raise(SIGSTOP);
        if (result != 0) {
            // If raise SIGSTOP failed we should abort cause something went
            // wrong and we don't have information to recover.
            SLOG(fatal) << "error raising SIGSTOP: " << std::strerror(errno);
            exit(1);
        }
        // When we wake up, we took the parent's place, so we are not "forked" anymore
        forked = false;
    }
}

static void snapshot(bool &forked) {
    SLOG(trace) << "snapshot called with forked: " << forked;
    pid_t childid = 0;
    squash_parent(forked);
    // Now actually fork
    if ((childid = fork()) == 0) {
        SLOG(trace) << "Child after fork will continue serving requests";
        // Child simply goes on with next loop iteration.
        forked = true;
    } else {
        SLOG(trace) << "Parent after fork will call waitpid";
        // Parent waits on child.
        int wstatus{};
        pid_t pid = waitpid(childid, &wstatus, WUNTRACED);
        SLOG(trace) << "Waitpid result: " << pid;
        if (pid == -1) {
            // If waitpid failed we should abort cause something went
            // wrong and we don't have information to recover.
            SLOG(fatal) << "Error on waitpid: " << std::strerror(errno);
            exit(1);
        }
        if (WIFSTOPPED(wstatus)) {
            SLOG(trace) << "Parent observed that the child has raised SIGSTOP and will send SIGCONT to it and exit";
            // Here the child wants to take our place.
            // Wake child and exit.
            kill(childid, SIGCONT);
            exit(0);
        } else {
            SLOG(trace) << "Parent observed that the child has exited. This process will take it's place";
            // Here the child exited.
            // We take its place, but are not "forked" anymore.
            // We go on with next loop iteration.
            forked = false;
        }
    }
}

static void rollback(bool &forked) {
    SLOG(trace) << "rollback called with forked: " << forked;
    if (forked) {
        SLOG(trace) << "Calling exit";
        // Here, we are a child and forked.
        // We simply exit so parent can take our place.
        exit(0);
    }
}

using machine_ptr = std::unique_ptr<machine>;

class handler_GetVersion final : public handler<Void, GetVersionResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<GetVersionResponse> *writer) override {
        hctx.s->RequestGetVersion(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<GetVersionResponse> *writer) override {
        (void) hctx;
        (void) req;
        GetVersionResponse resp;
        auto *version = resp.mutable_version();
        version->set_major(server_version_major);
        version->set_minor(server_version_minor);
        version->set_patch(server_version_patch);
        version->set_pre_release(server_version_pre_release);
        version->set_build(server_version_build);
        return finish_ok(writer, resp); // NOLINT: suppress warning caused by gRPC
    }

public:
    handler_GetVersion(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_SetCheckInTarget final : public handler<SetCheckInTargetRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, SetCheckInTargetRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestSetCheckInTarget(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, SetCheckInTargetRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        if (req->session_id().empty() || req->address().empty()) {
            return finish_with_error(writer, StatusCode::INVALID_ARGUMENT, "need non-empty session id and address");
        }
        Void resp;
        hctx.checkin = checkin_context{req->session_id(), req->address()};
        return finish_ok(writer, resp);
    }

public:
    handler_SetCheckInTarget(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Machine final : public handler<MachineRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, MachineRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestMachine(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, MachineRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        if (hctx.m) {
            return finish_with_error(writer, StatusCode::FAILED_PRECONDITION, "machine already exists");
        }
        Void resp;
        switch (req->machine_oneof_case()) {
            case MachineRequest::kConfig:
                hctx.m = std::make_unique<cartesi::machine>(get_proto_machine_config(req->config()),
                    get_proto_machine_runtime_config(req->runtime()));
                return finish_ok(writer, resp);
            case MachineRequest::kDirectory:
                hctx.m = std::make_unique<cartesi::machine>(req->directory(),
                    get_proto_machine_runtime_config(req->runtime()));
                return finish_ok(writer, resp);
            default:
                return finish_with_error(writer, StatusCode::INVALID_ARGUMENT, "invalid machine specification");
        }
    }

public:
    handler_Machine(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Run final : public handler<RunRequest, RunResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, RunRequest *req,
        ServerAsyncResponseWriter<RunResponse> *writer) override {
        hctx.s->RequestRun(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, RunRequest *req, ServerAsyncResponseWriter<RunResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        auto limit = static_cast<uint64_t>(req->limit());
        RunResponse resp;
        hctx.m->run(limit);
        resp.set_mcycle(hctx.m->read_mcycle());
        resp.set_tohost(hctx.m->read_htif_tohost());
        resp.set_iflags_h(hctx.m->read_iflags_H());
        resp.set_iflags_y(hctx.m->read_iflags_Y());
        resp.set_iflags_x(hctx.m->read_iflags_X());
        return finish_ok(writer, resp);
    }

public:
    handler_Run(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_RunUarch final : public handler<RunUarchRequest, RunUarchResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, RunUarchRequest *req,
        ServerAsyncResponseWriter<RunUarchResponse> *writer) override {
        hctx.s->RequestRunUarch(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, RunUarchRequest *req,
        ServerAsyncResponseWriter<RunUarchResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        auto limit = static_cast<uint64_t>(req->limit());
        RunUarchResponse resp;
        hctx.m->run_uarch(limit);
        resp.set_cycle(hctx.m->read_uarch_cycle());
        resp.set_pc(hctx.m->read_uarch_pc());
        resp.set_halt_flag(hctx.m->read_uarch_halt_flag());
        return finish_ok(writer, resp);
    }

public:
    handler_RunUarch(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Store final : public handler<StoreRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, StoreRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestStore(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, StoreRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        Void resp;
        hctx.m->store(req->directory());
        return finish_ok(writer, resp);
    }

public:
    handler_Store(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Destroy final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestDestroy(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) req;
        squash_parent(hctx.forked);
        if (hctx.m) {
            hctx.m.reset();
        }
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_Destroy(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Snapshot final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestSnapshot(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::snapshot;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) hctx;
        (void) req;
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_Snapshot(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Rollback final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestRollback(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::rollback;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) hctx;
        (void) req;
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_Rollback(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_Shutdown final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestShutdown(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::shutdown;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) hctx;
        (void) req;
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_Shutdown(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ResetUarchState final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestResetUarchState(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->reset_uarch_state();
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_ResetUarchState(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_StepUarch final : public handler<StepUarchRequest, StepUarchResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, StepUarchRequest *req,
        ServerAsyncResponseWriter<StepUarchResponse> *writer) override {
        hctx.s->RequestStepUarch(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, StepUarchRequest *req,
        ServerAsyncResponseWriter<StepUarchResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        AccessLog proto_log;
        StepUarchResponse resp;
        set_proto_access_log(hctx.m->step_uarch(get_proto_log_type(req->log_type()), req->one_based()),
            resp.mutable_log());
        return finish_ok(writer, resp);
    }

public:
    handler_StepUarch(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadMemory final : public handler<ReadMemoryRequest, ReadMemoryResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadMemoryRequest *req,
        ServerAsyncResponseWriter<ReadMemoryResponse> *writer) override {
        hctx.s->RequestReadMemory(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadMemoryRequest *req,
        ServerAsyncResponseWriter<ReadMemoryResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        uint64_t length = req->length();
        auto data = cartesi::unique_calloc<unsigned char>(length);
        hctx.m->read_memory(address, data.get(), length);
        ReadMemoryResponse resp;
        resp.set_data(data.get(), length);
        return finish_ok(writer, resp);
    }

public:
    handler_ReadMemory(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_WriteMemory final : public handler<WriteMemoryRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, WriteMemoryRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestWriteMemory(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, WriteMemoryRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        const auto &data = req->data();
        Void resp;

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        hctx.m->write_memory(address, reinterpret_cast<const unsigned char *>(data.data()), data.size());
        return finish_ok(writer, resp);
    }

public:
    handler_WriteMemory(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadVirtualMemory final : public handler<ReadMemoryRequest, ReadMemoryResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadMemoryRequest *req,
        ServerAsyncResponseWriter<ReadMemoryResponse> *writer) override {
        hctx.s->RequestReadVirtualMemory(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadMemoryRequest *req,
        ServerAsyncResponseWriter<ReadMemoryResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        uint64_t length = req->length();
        auto data = cartesi::unique_calloc<unsigned char>(length);
        hctx.m->read_virtual_memory(address, data.get(), length);
        ReadMemoryResponse resp;
        resp.set_data(data.get(), length);
        return finish_ok(writer, resp);
    }

public:
    handler_ReadVirtualMemory(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_WriteVirtualMemory final : public handler<WriteMemoryRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, WriteMemoryRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestWriteVirtualMemory(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, WriteMemoryRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        const auto &data = req->data();
        Void resp;

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        hctx.m->write_virtual_memory(address, reinterpret_cast<const unsigned char *>(data.data()), data.size());
        return finish_ok(writer, resp);
    }

public:
    handler_WriteVirtualMemory(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadWord final : public handler<ReadWordRequest, ReadWordResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadWordRequest *req,
        ServerAsyncResponseWriter<ReadWordResponse> *writer) override {
        hctx.s->RequestReadWord(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadWordRequest *req,
        ServerAsyncResponseWriter<ReadWordResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        ReadWordResponse resp;
        resp.set_value(hctx.m->read_word(address));
        resp.set_success(true);
        return finish_ok(writer, resp);
    }

public:
    handler_ReadWord(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetRootHash final : public handler<Void, GetRootHashResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<GetRootHashResponse> *writer) override {
        hctx.s->RequestGetRootHash(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<GetRootHashResponse> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        machine_merkle_tree::hash_type rh;
        hctx.m->get_root_hash(rh);
        GetRootHashResponse resp;
        set_proto_hash(rh, resp.mutable_hash());
        return finish_ok(writer, resp);
    }

public:
    handler_GetRootHash(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetProof final : public handler<GetProofRequest, GetProofResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, GetProofRequest *req,
        ServerAsyncResponseWriter<GetProofResponse> *writer) override {
        hctx.s->RequestGetProof(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, GetProofRequest *req,
        ServerAsyncResponseWriter<GetProofResponse> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        uint64_t address = req->address();
        int log2_size = static_cast<int>(req->log2_size());
        GetProofResponse resp;
        set_proto_merkle_tree_proof(hctx.m->get_proof(address, log2_size), resp.mutable_proof());
        return finish_ok(writer, resp);
    }

public:
    handler_GetProof(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReplaceMemoryRange final : public handler<ReplaceMemoryRangeRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReplaceMemoryRangeRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestReplaceMemoryRange(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReplaceMemoryRangeRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->replace_memory_range(get_proto_memory_range_config(req->config()));
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_ReplaceMemoryRange(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetXAddress final : public handler<GetXAddressRequest, GetXAddressResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, GetXAddressRequest *req,
        ServerAsyncResponseWriter<GetXAddressResponse> *writer) override {
        hctx.s->RequestGetXAddress(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, GetXAddressRequest *req,
        ServerAsyncResponseWriter<GetXAddressResponse> *writer) override {
        (void) hctx;
        auto index = req->index();
        if (index >= X_REG_COUNT) {
            throw std::invalid_argument{"invalid register index"};
        }
        GetXAddressResponse resp;
        resp.set_address(cartesi::machine::get_x_address(static_cast<int>(index)));
        return finish_ok(writer, resp);
    }

public:
    handler_GetXAddress(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadX final : public handler<ReadXRequest, ReadXResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadXRequest *req,
        ServerAsyncResponseWriter<ReadXResponse> *writer) override {
        hctx.s->RequestReadX(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadXRequest *req,
        ServerAsyncResponseWriter<ReadXResponse> *writer) override {
        auto index = req->index();
        if (index >= X_REG_COUNT) {
            throw std::invalid_argument{"invalid register index"};
        }
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        ReadXResponse resp;
        resp.set_value(hctx.m->read_x(static_cast<int>(index)));
        return finish_ok(writer, resp);
    }

public:
    handler_ReadX(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_WriteX final : public handler<WriteXRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, WriteXRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestWriteX(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, WriteXRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        auto index = req->index();
        if (index >= X_REG_COUNT || index <= 0) { // x0 is read-only
            throw std::invalid_argument{"invalid register index"};
        }
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->write_x(static_cast<int>(index), req->value());
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_WriteX(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetUarchXAddress final : public handler<GetUarchXAddressRequest, GetUarchXAddressResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, GetUarchXAddressRequest *req,
        ServerAsyncResponseWriter<GetUarchXAddressResponse> *writer) override {
        hctx.s->RequestGetUarchXAddress(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, GetUarchXAddressRequest *req,
        ServerAsyncResponseWriter<GetUarchXAddressResponse> *writer) override {
        (void) hctx;
        auto index = req->index();
        if (index >= UARCH_X_REG_COUNT) {
            throw std::invalid_argument{"invalid register index"};
        }
        GetUarchXAddressResponse resp;
        resp.set_address(cartesi::machine::get_uarch_x_address(static_cast<int>(index)));
        return finish_ok(writer, resp);
    }

public:
    handler_GetUarchXAddress(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadUarchX final : public handler<ReadUarchXRequest, ReadUarchXResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadUarchXRequest *req,
        ServerAsyncResponseWriter<ReadUarchXResponse> *writer) override {
        hctx.s->RequestReadUarchX(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadUarchXRequest *req,
        ServerAsyncResponseWriter<ReadUarchXResponse> *writer) override {
        auto index = req->index();
        if (index >= UARCH_X_REG_COUNT) {
            throw std::invalid_argument{"invalid register index"};
        }
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        ReadUarchXResponse resp;
        resp.set_value(hctx.m->read_uarch_x(static_cast<int>(index)));
        return finish_ok(writer, resp);
    }

public:
    handler_ReadUarchX(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_WriteUarchX final : public handler<WriteUarchXRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, WriteUarchXRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestWriteUarchX(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, WriteUarchXRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        auto index = req->index();
        if (index >= UARCH_X_REG_COUNT || index <= 0) { // x0 is read-only
            throw std::invalid_argument{"invalid register index"};
        }
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->write_uarch_x(static_cast<int>(index), req->value());
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_WriteUarchX(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ResetIflagsY final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestResetIflagsY(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->reset_iflags_Y();
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_ResetIflagsY(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetCsrAddress final : public handler<GetCsrAddressRequest, GetCsrAddressResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, GetCsrAddressRequest *req,
        ServerAsyncResponseWriter<GetCsrAddressResponse> *writer) override {
        hctx.s->RequestGetCsrAddress(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, GetCsrAddressRequest *req,
        ServerAsyncResponseWriter<GetCsrAddressResponse> *writer) override {
        (void) hctx;
        if (!CartesiMachine::Csr_IsValid(req->csr())) {
            throw std::invalid_argument{"invalid CSR"};
        }
        static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
        auto csr = static_cast<cartesi::machine::csr>(req->csr());
        GetCsrAddressResponse resp;
        resp.set_address(cartesi::machine::get_csr_address(csr));
        return finish_ok(writer, resp);
    }

public:
    handler_GetCsrAddress(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_ReadCsr final : public handler<ReadCsrRequest, ReadCsrResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, ReadCsrRequest *req,
        ServerAsyncResponseWriter<ReadCsrResponse> *writer) override {
        hctx.s->RequestReadCsr(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, ReadCsrRequest *req,
        ServerAsyncResponseWriter<ReadCsrResponse> *writer) override {
        if (!CartesiMachine::Csr_IsValid(req->csr())) {
            throw std::invalid_argument{"invalid CSR"};
        }
        static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
        auto csr = static_cast<cartesi::machine::csr>(req->csr());
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        ReadCsrResponse resp;
        resp.set_value(hctx.m->read_csr(csr));
        return finish_ok(writer, resp);
    }

public:
    handler_ReadCsr(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_WriteCsr final : public handler<WriteCsrRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, WriteCsrRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestWriteCsr(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, WriteCsrRequest *req, ServerAsyncResponseWriter<Void> *writer) override {
        if (!CartesiMachine::Csr_IsValid(req->csr())) {
            throw std::invalid_argument{"invalid CSR"};
        }
        static_assert(cartesi::machine::num_csr == Csr_ARRAYSIZE);
        auto csr = static_cast<cartesi::machine::csr>(req->csr());
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        Void resp;
        hctx.m->write_csr(csr, req->value());
        return finish_ok(writer, resp);
    }

public:
    handler_WriteCsr(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetInitialConfig final : public handler<Void, GetInitialConfigResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<GetInitialConfigResponse> *writer) override {
        hctx.s->RequestGetInitialConfig(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req,
        ServerAsyncResponseWriter<GetInitialConfigResponse> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        GetInitialConfigResponse resp;
        set_proto_machine_config(hctx.m->get_initial_config(), resp.mutable_config());
        return finish_ok(writer, resp);
    }

public:
    handler_GetInitialConfig(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_VerifyMerkleTree final : public handler<Void, VerifyMerkleTreeResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<VerifyMerkleTreeResponse> *writer) override {
        hctx.s->RequestVerifyMerkleTree(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req,
        ServerAsyncResponseWriter<VerifyMerkleTreeResponse> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        VerifyMerkleTreeResponse resp;
        resp.set_success(hctx.m->verify_merkle_tree());
        return finish_ok(writer, resp);
    }

public:
    handler_VerifyMerkleTree(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_VerifyDirtyPageMaps final : public handler<Void, VerifyDirtyPageMapsResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<VerifyDirtyPageMapsResponse> *writer) override {
        hctx.s->RequestVerifyDirtyPageMaps(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req,
        ServerAsyncResponseWriter<VerifyDirtyPageMapsResponse> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        VerifyDirtyPageMapsResponse resp;
        resp.set_success(hctx.m->verify_dirty_page_maps());
        return finish_ok(writer, resp);
    }

public:
    handler_VerifyDirtyPageMaps(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_DumpPmas final : public handler<Void, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestDumpPmas(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req, ServerAsyncResponseWriter<Void> *writer) override {
        (void) req;
        if (!hctx.m) {
            return finish_with_error_no_machine(writer);
        }
        hctx.m->dump_pmas();
        Void resp;
        return finish_ok(writer, resp);
    }

public:
    handler_DumpPmas(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_GetDefaultConfig final : public handler<Void, GetDefaultConfigResponse> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, Void *req,
        ServerAsyncResponseWriter<GetDefaultConfigResponse> *writer) override {
        hctx.s->RequestGetDefaultConfig(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, Void *req,
        ServerAsyncResponseWriter<GetDefaultConfigResponse> *writer) override {
        (void) hctx;
        (void) req;
        GetDefaultConfigResponse resp;
        set_proto_machine_config(machine::get_default_config(), resp.mutable_config());
        return finish_ok(writer, resp);
    }

public:
    handler_GetDefaultConfig(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_VerifyAccessLog final : public handler<VerifyAccessLogRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, VerifyAccessLogRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestVerifyAccessLog(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, VerifyAccessLogRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        (void) hctx;
        Void resp;
        machine::verify_access_log(get_proto_access_log(req->log()), get_proto_machine_runtime_config(req->runtime()),
            req->one_based());
        return finish_ok(writer, resp);
    }

public:
    handler_VerifyAccessLog(handler_context &hctx) {
        advance(hctx);
    }
};

class handler_VerifyStateTransition final : public handler<VerifyStateTransitionRequest, Void> {

    side_effect prepare(handler_context &hctx, ServerContext *sctx, VerifyStateTransitionRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        hctx.s->RequestVerifyStateTransition(sctx, req, writer, hctx.cq.get(), hctx.cq.get(), this);
        return side_effect::none;
    }

    side_effect go(handler_context &hctx, VerifyStateTransitionRequest *req,
        ServerAsyncResponseWriter<Void> *writer) override {
        (void) hctx;
        machine::verify_state_transition(get_proto_hash(req->root_hash_before()), get_proto_access_log(req->log()),
            get_proto_hash(req->root_hash_after()), get_proto_machine_runtime_config(req->runtime()), req->one_based());
        Void resp;
        return finish_ok(writer, resp); // NOLINT: suppress warning caused by gRPC
    }

public:
    handler_VerifyStateTransition(handler_context &hctx) {
        advance(hctx);
    }
};

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

std::unique_ptr<Server> build_server(const char *server_address, handler_context &hctx) {
    SLOG(debug) << "Building new GRPC server";
    hctx.s = std::make_unique<Machine::AsyncService>();
    ServerBuilder builder;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    int server_port = 0;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials(), &server_port);
    builder.RegisterService(hctx.s.get());
    hctx.cq = builder.AddCompletionQueue();
    auto server = builder.BuildAndStart();
    if (hctx.checkin.has_value()) {
        auto stub = MachineCheckIn::NewStub(
            grpc::CreateChannel(hctx.checkin.value().checkin_address, grpc::InsecureChannelCredentials()));
        CheckInRequest request;
        Void response;
        request.set_session_id(hctx.checkin.value().session_id);
        request.set_address(replace_port(server_address, server_port));
        SLOG(debug) << "Doing check-in. Session id: " << request.session_id() << " " << request.address();
        SLOG(debug) << "check-in timeout: " << checkin_deadline;
        for (uint64_t i = 1; i <= checkin_retry_attempts; i++) {
            SLOG(debug) << "check-in attempt: " << i;
            grpc::ClientContext context;
            context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(checkin_deadline));
            auto status = stub->CheckIn(&context, request, &response);
            if (status.ok()) {
                SLOG(debug) << "check-in succeeded!";
                return server;
            }
            SLOG(error) << "check-in failed. " << status.error_message();
            std::this_thread::sleep_for(checkin_retry_wait_time);
        }
        SLOG(fatal) << "unable to check-in";
        return nullptr;
    }
    return server;
}

static void tc_disable(void) {
    SLOG(trace) << "Registering handler for SIGTTOU";
    // prevent this process from suspending after issuing a SIGTTOU when trying
    // to configure terminal (on htif::init_console())
    //
    // https://pubs.opengroup.org/onlinepubs/009604599/basedefs/xbd_chap11.html#tag_11_01_04
    // https://pubs.opengroup.org/onlinepubs/009604499/functions/tcsetattr.html
    // http://curiousthing.org/sigttin-sigttou-deep-dive-linux
    struct sigaction tc {};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    tc.sa_handler = SIG_IGN;
    tc.sa_flags = SA_RESTART;
    if (sigemptyset(&tc.sa_mask) < 0) {
        throw std::system_error{errno, std::generic_category(), "sigemptyset failed"};
    }
    if (sigaction(SIGTTOU, &tc, nullptr) < 0) {
        throw std::system_error{errno, std::generic_category(), "sigaction failed"};
    }
}

static void server_loop(const char *server_address, const char *session_id, const char *checkin_address) {
    SLOG(info) << "Initializing server on " << server_address;
    handler_context hctx{};
    if (session_id && checkin_address) {
        SLOG(debug) << "Initializing checkin info: " << session_id << " " << checkin_address;
        hctx.checkin.emplace(session_id, checkin_address);
    }
    for (;;) {
        auto server = build_server(server_address, hctx);
        if (!server) {
            SLOG(fatal) << "Server creation failed";
            exit(1);
        }

        SLOG(trace) << "Registering GRPC handlers";
        handler_GetVersion hGetVersion(hctx);
        handler_SetCheckInTarget hSetCheckInTarget(hctx);
        handler_Machine hMachine(hctx);
        handler_Run hRun(hctx);
        handler_RunUarch hRunUarch(hctx);
        handler_ResetUarchState hResetUarchState(hctx);
        handler_Store hStore(hctx);
        handler_Destroy hDestroy(hctx);
        handler_Snapshot hSnapshot(hctx);
        handler_Rollback hRollback(hctx);
        handler_Shutdown hShutdown(hctx);
        handler_StepUarch hStepUarch(hctx);
        handler_ReadMemory hReadMemory(hctx);
        handler_WriteMemory hWriteMemory(hctx);
        handler_ReadVirtualMemory hReadVirtualMemory(hctx);
        handler_WriteVirtualMemory hWriteVirtualMemory(hctx);
        handler_ReadWord hReadWord(hctx);
        handler_GetRootHash hGetRootHash(hctx);
        handler_GetProof hGetProof(hctx);
        handler_ReplaceMemoryRange hReplaceMemoryRange(hctx);
        handler_GetXAddress hGetXAddress(hctx);
        handler_ReadX hReadX(hctx);
        handler_WriteX hWriteX(hctx);
        handler_GetUarchXAddress hGetUarchXAddress(hctx);
        handler_ReadUarchX hReadUarchX(hctx);
        handler_WriteUarchX hWriteUarchX(hctx);
        handler_ResetIflagsY hResetIflagsY(hctx);
        handler_GetCsrAddress hGetCsrAddress(hctx);
        handler_ReadCsr hReadCsr(hctx);
        handler_WriteCsr hWriteCsr(hctx);
        handler_GetInitialConfig hGetInitialConfig(hctx);
        handler_VerifyMerkleTree hVerifyMerkleTree(hctx);
        handler_VerifyDirtyPageMaps hVerifyDirtyPageMaps(hctx);
        handler_DumpPmas hDumpPmas(hctx);
        handler_GetDefaultConfig hGetDefaultConfig(hctx);
        handler_VerifyAccessLog hVerifyAccessLog(hctx);
        handler_VerifyStateTransition hVerifyStateTransition(hctx);

        // The invariant before and after snapshot/rollbacks is that all handlers
        // are in waiting mode
        using side_effect = i_handler::side_effect;
        side_effect s_effect = side_effect::none;
        for (;;) {
            SLOG(debug) << "Waiting next request";
            i_handler *h = nullptr;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            if (!hctx.cq->Next(reinterpret_cast<void **>(&h), &hctx.ok)) {
                s_effect = side_effect::shutdown;
                SLOG(debug) << "Breaking from server loop with side effect == shutdown";
                break;
            }
            if ((s_effect = h->advance(hctx)) != side_effect::none) {
                SLOG(debug) << "Breaking from server loop with side effect != none";
                break;
            }
        }

        SLOG(trace) << "Start GRPC server shutdown";
        // Shutdown server and completion queue before handling side effect
        // Server must be shutdown before completion queue
        server->Shutdown(std::chrono::system_clock::now());
        SLOG(trace) << "GRPC completion queue shutdown";
        hctx.cq->Shutdown();
        {
            // Drain completion queue before exiting
            bool ok = false;
            i_handler *h = nullptr;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            while (hctx.cq->Next(reinterpret_cast<void **>(&h), &ok)) {
                ;
            }
        }
        SLOG(trace) << "Waiting GRPC server to finish shutdown";
        server->Wait();
        // Release and delete
        server.reset(nullptr);
        hctx.s.reset(nullptr);
        hctx.cq.reset(nullptr);

        // Handle side effect
        switch (s_effect) {
            case side_effect::none:
                SLOG(debug) << "Handling side effect side effect none";
                // do nothing
                break;
            case side_effect::snapshot:
                SLOG(debug) << "Handling side effect side effect snapshot";
                snapshot(hctx.forked);
                break;
            case side_effect::rollback:
                SLOG(debug) << "Handling side effect side effect rollback";
                rollback(hctx.forked);
                break;
            case side_effect::shutdown:
                SLOG(debug) << "Handling side effect side effect shutdown";
                // Make sure we don't leave a snapshot burried
                squash_parent(hctx.forked);
                return;
        }
    }
}

/// \brief Checks if string matches prefix and captures remaninder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remaninder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    size_t len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        *val = str + len;
        return true;
    }
    return false;
}

static void help(const char *name) {
    (void) fprintf(stderr,
        R"(Usage:

	%s [options] [<server-address>]

where

    --server-address=<server-address> or [<server-address>]
      gives the address of the server
      <server-address> can be
        <ipv4-hostname/address>:<port>
        <ipv6-hostname/address>:<port>
        unix:<path>
      when <port> is 0, an ephemeral port will be automatically selected

and options are

    --checkin-address=<checkin-address>
      address to which a check-in message will be sent informing the
      new server is ready. The check-in message also informs the <port>
      selected for the server and the session id <string>

    --session-id=<string>
      arbitrary string used when sending the check-in message

    --log-level=<level>
      sets the log level
      <level> can be
        trace
        debug
        info
        warn
        error
        fatal
      the command line option takes precedence over the environment variable
      REMOTE_CARTESI_MACHINE_LOG_LEVEL

    --help
      prints this message and exits

)",
        name);
}

static void init_logger(const char *strlevel) {
    using namespace slog;
    severity_level level = severity_level::info;
    if (!strlevel) {
        strlevel = std::getenv("REMOTE_CARTESI_MACHINE_LOG_LEVEL");
    }
    if (strlevel) {
        level = from_string(strlevel);
    }
    log_level(level_operation::set, level);
}

int main(int argc, char *argv[]) try {

    const char *server_address = nullptr;
    const char *session_id = nullptr;
    const char *checkin_address = nullptr;
    const char *program_name = PROGRAM_NAME;
    const char *log_level = nullptr;

    if (argc > 0) { // NOLINT: of course it could be == 0...
        program_name = argv[0];
    }

    for (int i = 1; i < argc; i++) {
        if (stringval("--server-address=", argv[i], &server_address)) {
            ;
        } else if (stringval("--checkin-address=", argv[i], &checkin_address)) {
            ;
        } else if (stringval("--session-id=", argv[i], &session_id)) {
            ;
        } else if (stringval("--log-level=", argv[i], &log_level)) {
            ;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(program_name);
            exit(0);
        } else {
            if (!server_address) {
                server_address = argv[i];
            } else {
                std::cerr << "repeated [<server-address>] option";
                exit(1);
            }
        }
    }

    if (!server_address) {
        std::cerr << "missing server-address\n";
        exit(1);
    }

    if ((session_id == nullptr) != (checkin_address == nullptr)) {
        std::cerr << "session-id and checkin-address must be used together\n";
        exit(1);
    }

    init_logger(log_level);
    tc_disable();
    server_loop(server_address, session_id, checkin_address);

    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
