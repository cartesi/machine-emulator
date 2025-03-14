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

#include "machine-c-api.h"

#include <any>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <typeinfo>
#include <variant>

#include "access-log.h"
#include "address-range-defines.h"
#include "address-range-description.h"
#include "htif-constants.h"
#include "i-machine.h"
#include "interpret.h"
#include "json-util.h"
#include "local-machine.h"
#include "machine-c-api-internal.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "os-features.h"

static std::string &get_last_err_msg_storage() {
    static THREAD_LOCAL std::string last_err_msg;
    return last_err_msg;
}

static_assert(AR_CMIO_RX_BUFFER_START_DEF == CM_AR_CMIO_RX_BUFFER_START);
static_assert(AR_CMIO_RX_BUFFER_LOG2_SIZE_DEF == CM_AR_CMIO_RX_BUFFER_LOG2_SIZE);
static_assert(AR_CMIO_TX_BUFFER_START_DEF == CM_AR_CMIO_TX_BUFFER_START);
static_assert(AR_CMIO_TX_BUFFER_LOG2_SIZE_DEF == CM_AR_CMIO_TX_BUFFER_LOG2_SIZE);
static_assert(AR_RAM_START_DEF == CM_AR_RAM_START);

static_assert(HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF == CM_CMIO_YIELD_AUTOMATIC_REASON_PROGRESS);
static_assert(HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF == CM_CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT);
static_assert(HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT_DEF == CM_CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT);
static_assert(HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF == CM_CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED);
static_assert(HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF == CM_CMIO_YIELD_MANUAL_REASON_RX_REJECTED);
static_assert(HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION_DEF == CM_CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION);
static_assert(HTIF_YIELD_REASON_ADVANCE_STATE_DEF == CM_CMIO_YIELD_REASON_ADVANCE_STATE);
static_assert(HTIF_YIELD_REASON_INSPECT_STATE_DEF == CM_CMIO_YIELD_REASON_INSPECT_STATE);

const char *cm_get_last_error_message() {
    return get_last_err_msg_storage().c_str();
}

const char *cm_set_temp_string(const std::string &s) {
    static THREAD_LOCAL std::string temp_string;
    temp_string = s;
    return temp_string.c_str();
}

cm_error cm_result_failure() try { throw; } catch (const std::exception &e) {
    try {
        get_last_err_msg_storage() = e.what();
        throw;
    } catch (const std::invalid_argument &ex) {
        return CM_ERROR_INVALID_ARGUMENT;
    } catch (const std::domain_error &ex) {
        return CM_ERROR_DOMAIN_ERROR;
    } catch (const std::length_error &ex) {
        return CM_ERROR_LENGTH_ERROR;
    } catch (const std::out_of_range &ex) {
        return CM_ERROR_OUT_OF_RANGE;
    } catch (const std::logic_error &ex) {
        return CM_ERROR_LOGIC_ERROR;
    } catch (const std::bad_optional_access &ex) {
        return CM_ERROR_BAD_OPTIONAL_ACCESS;
    } catch (const std::range_error &ex) {
        return CM_ERROR_RANGE_ERROR;
    } catch (const std::overflow_error &ex) {
        return CM_ERROR_OVERFLOW_ERROR;
    } catch (const std::underflow_error &ex) {
        return CM_ERROR_UNDERFLOW_ERROR;
    } catch (const std::regex_error &ex) {
        return CM_ERROR_REGEX_ERROR;
    } catch (const std::system_error &ex) {
        return CM_ERROR_SYSTEM_ERROR;
    } catch (const std::runtime_error &ex) {
        return CM_ERROR_RUNTIME_ERROR;
    } catch (const std::bad_typeid &ex) {
        return CM_ERROR_BAD_TYPEID;
    } catch (const std::bad_any_cast &ex) {
        return CM_ERROR_BAD_ANY_CAST;
    } catch (const std::bad_cast &ex) {
        return CM_ERROR_BAD_CAST;
    } catch (const std::bad_weak_ptr &ex) {
        return CM_ERROR_BAD_WEAK_PTR;
    } catch (const std::bad_function_call &ex) {
        return CM_ERROR_BAD_FUNCTION_CALL;
    } catch (const std::bad_array_new_length &ex) {
        return CM_ERROR_BAD_ARRAY_NEW_LENGTH;
    } catch (const std::bad_alloc &ex) {
        return CM_ERROR_BAD_ALLOC;
    } catch (const std::bad_exception &ex) {
        return CM_ERROR_BAD_EXCEPTION;
    } catch (const std::bad_variant_access &ex) {
        return CM_ERROR_BAD_VARIANT_ACCESS;
    } catch (const std::exception &e) {
        return CM_ERROR_EXCEPTION;
    }
} catch (...) {
    try {
        get_last_err_msg_storage() = std::string("unknown error");
    } catch (...) {
        // Failed to allocate string, last resort is to set an empty error.
        get_last_err_msg_storage().clear();
    }
    return CM_ERROR_UNKNOWN;
}

cm_error cm_result_success() {
    get_last_err_msg_storage().clear();
    return CM_ERROR_OK;
}

// --------------------------------------------
// Conversion functions
// --------------------------------------------

static cartesi::machine_reg convert_from_c(cm_reg r) {
    using reg = cartesi::machine_reg;
    switch (r) {
        case CM_REG_X0:
            return reg::x0;
        case CM_REG_X1:
            return reg::x1;
        case CM_REG_X2:
            return reg::x2;
        case CM_REG_X3:
            return reg::x3;
        case CM_REG_X4:
            return reg::x4;
        case CM_REG_X5:
            return reg::x5;
        case CM_REG_X6:
            return reg::x6;
        case CM_REG_X7:
            return reg::x7;
        case CM_REG_X8:
            return reg::x8;
        case CM_REG_X9:
            return reg::x9;
        case CM_REG_X10:
            return reg::x10;
        case CM_REG_X11:
            return reg::x11;
        case CM_REG_X12:
            return reg::x12;
        case CM_REG_X13:
            return reg::x13;
        case CM_REG_X14:
            return reg::x14;
        case CM_REG_X15:
            return reg::x15;
        case CM_REG_X16:
            return reg::x16;
        case CM_REG_X17:
            return reg::x17;
        case CM_REG_X18:
            return reg::x18;
        case CM_REG_X19:
            return reg::x19;
        case CM_REG_X20:
            return reg::x20;
        case CM_REG_X21:
            return reg::x21;
        case CM_REG_X22:
            return reg::x22;
        case CM_REG_X23:
            return reg::x23;
        case CM_REG_X24:
            return reg::x24;
        case CM_REG_X25:
            return reg::x25;
        case CM_REG_X26:
            return reg::x26;
        case CM_REG_X27:
            return reg::x27;
        case CM_REG_X28:
            return reg::x28;
        case CM_REG_X29:
            return reg::x29;
        case CM_REG_X30:
            return reg::x30;
        case CM_REG_X31:
            return reg::x31;
        case CM_REG_F0:
            return reg::f0;
        case CM_REG_F1:
            return reg::f1;
        case CM_REG_F2:
            return reg::f2;
        case CM_REG_F3:
            return reg::f3;
        case CM_REG_F4:
            return reg::f4;
        case CM_REG_F5:
            return reg::f5;
        case CM_REG_F6:
            return reg::f6;
        case CM_REG_F7:
            return reg::f7;
        case CM_REG_F8:
            return reg::f8;
        case CM_REG_F9:
            return reg::f9;
        case CM_REG_F10:
            return reg::f10;
        case CM_REG_F11:
            return reg::f11;
        case CM_REG_F12:
            return reg::f12;
        case CM_REG_F13:
            return reg::f13;
        case CM_REG_F14:
            return reg::f14;
        case CM_REG_F15:
            return reg::f15;
        case CM_REG_F16:
            return reg::f16;
        case CM_REG_F17:
            return reg::f17;
        case CM_REG_F18:
            return reg::f18;
        case CM_REG_F19:
            return reg::f19;
        case CM_REG_F20:
            return reg::f20;
        case CM_REG_F21:
            return reg::f21;
        case CM_REG_F22:
            return reg::f22;
        case CM_REG_F23:
            return reg::f23;
        case CM_REG_F24:
            return reg::f24;
        case CM_REG_F25:
            return reg::f25;
        case CM_REG_F26:
            return reg::f26;
        case CM_REG_F27:
            return reg::f27;
        case CM_REG_F28:
            return reg::f28;
        case CM_REG_F29:
            return reg::f29;
        case CM_REG_F30:
            return reg::f30;
        case CM_REG_F31:
            return reg::f31;
        case CM_REG_PC:
            return reg::pc;
        case CM_REG_FCSR:
            return reg::fcsr;
        case CM_REG_MVENDORID:
            return reg::mvendorid;
        case CM_REG_MARCHID:
            return reg::marchid;
        case CM_REG_MIMPID:
            return reg::mimpid;
        case CM_REG_MCYCLE:
            return reg::mcycle;
        case CM_REG_ICYCLEINSTRET:
            return reg::icycleinstret;
        case CM_REG_MSTATUS:
            return reg::mstatus;
        case CM_REG_MTVEC:
            return reg::mtvec;
        case CM_REG_MSCRATCH:
            return reg::mscratch;
        case CM_REG_MEPC:
            return reg::mepc;
        case CM_REG_MCAUSE:
            return reg::mcause;
        case CM_REG_MTVAL:
            return reg::mtval;
        case CM_REG_MISA:
            return reg::misa;
        case CM_REG_MIE:
            return reg::mie;
        case CM_REG_MIP:
            return reg::mip;
        case CM_REG_MEDELEG:
            return reg::medeleg;
        case CM_REG_MIDELEG:
            return reg::mideleg;
        case CM_REG_MCOUNTEREN:
            return reg::mcounteren;
        case CM_REG_MENVCFG:
            return reg::menvcfg;
        case CM_REG_STVEC:
            return reg::stvec;
        case CM_REG_SSCRATCH:
            return reg::sscratch;
        case CM_REG_SEPC:
            return reg::sepc;
        case CM_REG_SCAUSE:
            return reg::scause;
        case CM_REG_STVAL:
            return reg::stval;
        case CM_REG_SATP:
            return reg::satp;
        case CM_REG_SCOUNTEREN:
            return reg::scounteren;
        case CM_REG_SENVCFG:
            return reg::senvcfg;
        case CM_REG_ILRSC:
            return reg::ilrsc;
        case CM_REG_IPRV:
            return reg::iprv;
        case CM_REG_IFLAGS_X:
            return reg::iflags_X;
        case CM_REG_IFLAGS_Y:
            return reg::iflags_Y;
        case CM_REG_IFLAGS_H:
            return reg::iflags_H;
        case CM_REG_IUNREP:
            return reg::iunrep;
        case CM_REG_CLINT_MTIMECMP:
            return reg::clint_mtimecmp;
        case CM_REG_PLIC_GIRQPEND:
            return reg::plic_girqpend;
        case CM_REG_PLIC_GIRQSRVD:
            return reg::plic_girqsrvd;
        case CM_REG_HTIF_TOHOST:
            return reg::htif_tohost;
        case CM_REG_HTIF_FROMHOST:
            return reg::htif_fromhost;
        case CM_REG_HTIF_IHALT:
            return reg::htif_ihalt;
        case CM_REG_HTIF_ICONSOLE:
            return reg::htif_iconsole;
        case CM_REG_HTIF_IYIELD:
            return reg::htif_iyield;
        case CM_REG_UARCH_X0:
            return reg::uarch_x0;
        case CM_REG_UARCH_X1:
            return reg::uarch_x1;
        case CM_REG_UARCH_X2:
            return reg::uarch_x2;
        case CM_REG_UARCH_X3:
            return reg::uarch_x3;
        case CM_REG_UARCH_X4:
            return reg::uarch_x4;
        case CM_REG_UARCH_X5:
            return reg::uarch_x5;
        case CM_REG_UARCH_X6:
            return reg::uarch_x6;
        case CM_REG_UARCH_X7:
            return reg::uarch_x7;
        case CM_REG_UARCH_X8:
            return reg::uarch_x8;
        case CM_REG_UARCH_X9:
            return reg::uarch_x9;
        case CM_REG_UARCH_X10:
            return reg::uarch_x10;
        case CM_REG_UARCH_X11:
            return reg::uarch_x11;
        case CM_REG_UARCH_X12:
            return reg::uarch_x12;
        case CM_REG_UARCH_X13:
            return reg::uarch_x13;
        case CM_REG_UARCH_X14:
            return reg::uarch_x14;
        case CM_REG_UARCH_X15:
            return reg::uarch_x15;
        case CM_REG_UARCH_X16:
            return reg::uarch_x16;
        case CM_REG_UARCH_X17:
            return reg::uarch_x17;
        case CM_REG_UARCH_X18:
            return reg::uarch_x18;
        case CM_REG_UARCH_X19:
            return reg::uarch_x19;
        case CM_REG_UARCH_X20:
            return reg::uarch_x20;
        case CM_REG_UARCH_X21:
            return reg::uarch_x21;
        case CM_REG_UARCH_X22:
            return reg::uarch_x22;
        case CM_REG_UARCH_X23:
            return reg::uarch_x23;
        case CM_REG_UARCH_X24:
            return reg::uarch_x24;
        case CM_REG_UARCH_X25:
            return reg::uarch_x25;
        case CM_REG_UARCH_X26:
            return reg::uarch_x26;
        case CM_REG_UARCH_X27:
            return reg::uarch_x27;
        case CM_REG_UARCH_X28:
            return reg::uarch_x28;
        case CM_REG_UARCH_X29:
            return reg::uarch_x29;
        case CM_REG_UARCH_X30:
            return reg::uarch_x30;
        case CM_REG_UARCH_X31:
            return reg::uarch_x31;
        case CM_REG_UARCH_PC:
            return reg::uarch_pc;
        case CM_REG_UARCH_CYCLE:
            return reg::uarch_cycle;
        case CM_REG_UARCH_HALT_FLAG:
            return reg::uarch_halt_flag;
        case CM_REG_HTIF_TOHOST_DEV:
            return reg::htif_tohost_dev;
        case CM_REG_HTIF_TOHOST_CMD:
            return reg::htif_tohost_cmd;
        case CM_REG_HTIF_TOHOST_REASON:
            return reg::htif_tohost_reason;
        case CM_REG_HTIF_TOHOST_DATA:
            return reg::htif_tohost_data;
        case CM_REG_HTIF_FROMHOST_DEV:
            return reg::htif_fromhost_dev;
        case CM_REG_HTIF_FROMHOST_CMD:
            return reg::htif_fromhost_cmd;
        case CM_REG_HTIF_FROMHOST_REASON:
            return reg::htif_fromhost_reason;
        case CM_REG_HTIF_FROMHOST_DATA:
            return reg::htif_fromhost_data;
        case CM_REG_UNKNOWN_:
            return reg::unknown_;
    }
    throw std::domain_error{"unknown register"};
}

static cartesi::i_machine *convert_from_c(cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::i_machine *>(m);
}

static const cartesi::i_machine *convert_from_c(const cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::i_machine *>(m);
}

static cm_machine *convert_to_c(cartesi::i_machine *cpp_m) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cm_machine *>(cpp_m);
}

static cartesi::machine_hash convert_from_c(const cm_hash *c_hash) {
    if (c_hash == nullptr) {
        throw std::invalid_argument("invalid hash");
    }
    cartesi::machine_hash cpp_hash; // In emulator this is std::array<unsigned char, hash_size>;
    memcpy(cpp_hash.data(), c_hash, sizeof(cm_hash));
    return cpp_hash;
}

// ----------------------------------------------
// The C API implementation
// ----------------------------------------------

cm_error cm_new(cm_machine **new_m) try {
    if (new_m == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    *new_m = convert_to_c(new cartesi::local_machine());
    return cm_result_success();
} catch (...) {
    if (new_m != nullptr) {
        *new_m = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_clone_empty(const cm_machine *m, cm_machine **new_m) try {
    if (new_m == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_m = convert_from_c(m);
    *new_m = convert_to_c(cpp_m->clone_empty());
    return cm_result_success();
} catch (...) {
    if (new_m != nullptr) {
        *new_m = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_is_empty(const cm_machine *m, bool *yes) try {
    if (yes == nullptr) {
        throw std::invalid_argument("invalid yes output");
    }
    const auto *cpp_m = convert_from_c(m);
    *yes = cpp_m->is_empty();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_create(cm_machine *m, const char *config, const char *runtime_config) try {
    auto *cpp_m = convert_from_c(m);
    if (config == nullptr) {
        throw std::invalid_argument("invalid machine configuration");
    }
    const auto c = cartesi::from_json<cartesi::machine_config>(config, "config");
    cartesi::machine_runtime_config r;
    if (runtime_config != nullptr) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config, "runtime_config");
    }
    cpp_m->create(c, r);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_load(cm_machine *m, const char *dir, const char *runtime_config) try {
    auto *cpp_m = convert_from_c(m);
    if (dir == nullptr) {
        throw std::invalid_argument("invalid dir");
    }
    cartesi::machine_runtime_config r;
    if (runtime_config != nullptr) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config, "runtime_config");
    }
    cpp_m->load(dir, r);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_load_new(const char *dir, const char *runtime_config, cm_machine **new_m) {
    auto err = cm_new(new_m);
    if (err != 0) {
        return err;
    }
    err = cm_load(*new_m, dir, runtime_config);
    if (err != 0) {
        cm_delete(*new_m);
        *new_m = nullptr;
    }
    return err;
}

cm_error cm_create_new(const char *config, const char *runtime_config, cm_machine **new_m) {
    auto err = cm_new(new_m);
    if (err != 0) {
        return err;
    }
    err = cm_create(*new_m, config, runtime_config);
    if (err != 0) {
        cm_delete(*new_m);
        *new_m = nullptr;
    }
    return err;
}

cm_error cm_store(const cm_machine *m, const char *dir) try {
    if (dir == nullptr) {
        throw std::invalid_argument("invalid dir");
    }
    const auto *cpp_m = convert_from_c(m);
    cpp_m->store(dir);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_run(cm_machine *m, uint64_t mcycle_end, cm_break_reason *break_reason) try {
    auto *cpp_m = convert_from_c(m);
    const auto status = cpp_m->run(mcycle_end);
    if (break_reason != nullptr) {
        *break_reason = static_cast<cm_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (break_reason != nullptr) {
        *break_reason = CM_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

cm_error cm_reset_uarch(cm_machine *m) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->reset_uarch();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_log_reset_uarch(cm_machine *m, int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_m = convert_from_c(m);
    const cartesi::access_log::type cpp_log_type(log_type);
    const cartesi::access_log cpp_log = cpp_m->log_reset_uarch(cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log != nullptr) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, cm_uarch_break_reason *uarch_break_reason) try {
    auto *cpp_m = convert_from_c(m);
    const auto status = cpp_m->run_uarch(uarch_cycle_end);
    if (uarch_break_reason != nullptr) {
        *uarch_break_reason = static_cast<cm_uarch_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (uarch_break_reason != nullptr) {
        *uarch_break_reason = CM_UARCH_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

CM_API cm_error cm_log_step(cm_machine *m, uint64_t mcycle_count, const char *log_filename,
    cm_break_reason *break_reason) try {
    if (log_filename == nullptr) {
        throw std::invalid_argument("invalid log_filename");
    }
    auto *cpp_m = convert_from_c(m);
    const auto status = cpp_m->log_step(mcycle_count, log_filename);
    if (break_reason != nullptr) {
        *break_reason = static_cast<cm_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (break_reason != nullptr) {
        *break_reason = CM_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

cm_error cm_log_step_uarch(cm_machine *m, int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_m = convert_from_c(m);
    const cartesi::access_log::type cpp_log_type(log_type);
    const cartesi::access_log cpp_log = cpp_m->log_step_uarch(cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log != nullptr) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_verify_step(const cm_machine *m, const cm_hash *root_hash_before, const char *log_filename,
    uint64_t mcycle_count, const cm_hash *root_hash_after, cm_break_reason *break_reason) try {
    if (log_filename == nullptr) {
        throw std::invalid_argument("invalid log_filename");
    }
    const cartesi::machine_hash cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine_hash cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::interpreter_break_reason status{};
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        status = cpp_m->verify_step(cpp_root_hash_before, log_filename, mcycle_count, cpp_root_hash_after);
    } else {
        status = cartesi::machine::verify_step(cpp_root_hash_before, log_filename, mcycle_count, cpp_root_hash_after);
    }
    if (break_reason != nullptr) {
        *break_reason = static_cast<cm_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (break_reason != nullptr) {
        *break_reason = CM_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

cm_error cm_verify_step_uarch(const cm_machine *m, const cm_hash *root_hash_before, const char *log,
    const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log, "log").value();
    const cartesi::machine_hash cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine_hash cpp_root_hash_after = convert_from_c(root_hash_after);
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        cpp_m->verify_step_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    } else {
        cartesi::machine::verify_step_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_verify_reset_uarch(const cm_machine *m, const cm_hash *root_hash_before, const char *log,
    const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log, "log").value();
    const cartesi::machine_hash cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine_hash cpp_root_hash_after = convert_from_c(root_hash_after);
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        cpp_m->verify_reset_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    } else {
        cartesi::machine::verify_reset_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_proof(const cm_machine *m, uint64_t address, int32_t log2_size, const char **proof) try {
    if (proof == nullptr) {
        throw std::invalid_argument("invalid proof output");
    }
    const auto *cpp_m = convert_from_c(m);
    const cartesi::i_machine::proof_type cpp_proof = cpp_m->get_proof(address, log2_size);
    *proof = cm_set_temp_string(cartesi::to_json(cpp_proof).dump());
    return cm_result_success();
} catch (...) {
    if (proof != nullptr) {
        *proof = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_get_root_hash(const cm_machine *m, cm_hash *hash) try {
    if (hash == nullptr) {
        throw std::invalid_argument("invalid hash output");
    }
    const auto *cpp_m = convert_from_c(m);
    cartesi::machine_hash cpp_hash = cpp_m->get_root_hash();
    using elem_t = std::ranges::range_value_t<cm_hash>;
    constexpr auto elem_n = std::extent_v<cm_hash>;
    static_assert(std::ranges::size(cpp_hash) == elem_n);
    std::ranges::copy(cpp_hash | cartesi::views::cast_to<elem_t>, std::ranges::data(*hash));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_node_hash(const cm_machine *m, uint64_t address, int log2_size, cm_hash *hash) try {
    if (hash == nullptr) {
        throw std::invalid_argument("invalid hash output");
    }
    const auto *cpp_m = convert_from_c(m);
    cartesi::machine_hash cpp_hash = cpp_m->get_node_hash(address, log2_size);
    using elem_t = std::ranges::range_value_t<cm_hash>;
    constexpr auto elem_n = std::extent_v<cm_hash>;
    static_assert(std::ranges::size(cpp_hash) == elem_n);
    std::ranges::copy(cpp_hash | cartesi::views::cast_to<elem_t>, std::ranges::data(*hash));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_verify_hash_tree(cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    auto *cpp_m = convert_from_c(m);
    *result = cpp_m->verify_hash_tree();
    return cm_result_success();
} catch (...) {
    if (result != nullptr) {
        *result = false;
    }
    return cm_result_failure();
}

cm_error cm_read_reg(const cm_machine *m, cm_reg reg, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_m = convert_from_c(m);
    auto cpp_reg = convert_from_c(reg);
    *val = cpp_m->read_reg(cpp_reg);
    return cm_result_success();
} catch (...) {
    if (val != nullptr) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_write_reg(cm_machine *m, cm_reg reg, uint64_t val) try {
    auto *cpp_m = convert_from_c(m);
    auto cpp_reg = convert_from_c(reg);
    cpp_m->write_reg(cpp_reg, val);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_reg_address(const cm_machine *m, cm_reg reg, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    auto cpp_reg = convert_from_c(reg);
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        *val = cpp_m->get_reg_address(cpp_reg);
    } else {
        *val = cartesi::machine::get_reg_address(cpp_reg);
    }
    return cm_result_success();
} catch (...) {
    if (val != nullptr) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid word output");
    }
    const auto *cpp_m = convert_from_c(m);
    *val = cpp_m->read_word(address);
    return cm_result_success();
} catch (...) {
    if (val != nullptr) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    const auto *cpp_m = convert_from_c(m);
    cpp_m->read_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_write_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->write_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_read_virtual_memory(cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->read_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_write_virtual_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->write_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_translate_virtual_address(cm_machine *m, uint64_t vaddr, uint64_t *paddr) try {
    auto *cpp_m = convert_from_c(m);
    *paddr = cpp_m->translate_virtual_address(vaddr);
    return cm_result_success();
} catch (...) {
    if (paddr != nullptr) {
        *paddr = 0;
    }
    return cm_result_failure();
}

cm_error cm_get_initial_config(const cm_machine *m, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_m = convert_from_c(m);
    const cartesi::machine_config cpp_config = cpp_m->get_initial_config();
    *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    if (config != nullptr) {
        *config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_get_runtime_config(const cm_machine *m, const char **runtime_config) try {
    if (runtime_config == nullptr) {
        throw std::invalid_argument("invalid runtime_config output");
    }
    const auto *cpp_m = convert_from_c(m);
    const cartesi::machine_runtime_config cpp_runtime_config = cpp_m->get_runtime_config();
    *runtime_config = cm_set_temp_string(cartesi::to_json(cpp_runtime_config).dump());
    return cm_result_success();
} catch (...) {
    if (runtime_config != nullptr) {
        *runtime_config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_set_runtime_config(cm_machine *m, const char *runtime_config) try {
    if (runtime_config == nullptr) {
        throw std::invalid_argument("invalid machine runtime configuration");
    }
    auto r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config, "runtime_config");
    auto *cpp_m = convert_from_c(m);
    cpp_m->set_runtime_config(r);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_default_config(const cm_machine *m, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        const cartesi::machine_config cpp_config = cpp_m->get_default_config();
        *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    } else {
        const cartesi::machine_config cpp_config = cartesi::machine::get_default_config();
        *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    }
    return cm_result_success();
} catch (...) {
    if (config != nullptr) {
        *config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_replace_memory_range(cm_machine *m, const char *range_config) try {
    auto *cpp_m = convert_from_c(m);
    if (range_config == nullptr) {
        throw std::invalid_argument("invalid memory range configuration");
    }
    const auto cpp_range = cartesi::from_json<cartesi::memory_range_config>(range_config, "range_config");
    cpp_m->replace_memory_range(cpp_range);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_delete(cm_machine *m) {
    if (m != nullptr) {
        auto *cpp_m = convert_from_c(m);
        delete cpp_m;
    }
}

cm_error cm_destroy(cm_machine *m) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->destroy();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_address_ranges(const cm_machine *m, const char **ranges) try {
    if (ranges == nullptr) {
        throw std::invalid_argument("invalid memory range output");
    }
    const auto *cpp_m = convert_from_c(m);
    const cartesi::address_range_descriptions cpp_ranges = cpp_m->get_address_ranges();
    *ranges = cm_set_temp_string(cartesi::to_json(cpp_ranges).dump());
    return cm_result_success();
} catch (...) {
    if (ranges != nullptr) {
        *ranges = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_receive_cmio_request(const cm_machine *m, uint8_t *cmd, uint16_t *reason, uint8_t *data,
    uint64_t *length) try {
    if (length == nullptr) {
        throw std::invalid_argument("invalid length output");
    }
    const auto *cpp_m = convert_from_c(m);
    // NOTE(edubart): This can be implemented on top of other APIs,
    // implementing in the C++ machine class would add lot of boilerplate code in all interfaces.
    if ((cpp_m->read_reg(cartesi::machine::reg::iflags_X) == 0) &&
        (cpp_m->read_reg(cartesi::machine::reg::iflags_Y) == 0)) {
        throw std::runtime_error{"machine is not yielded"};
    }
    const uint64_t tohost = cpp_m->read_reg(cartesi::machine::reg::htif_tohost);
    const uint8_t tohost_cmd = cartesi::HTIF_CMD_FIELD(tohost);
    const uint16_t tohost_reason = cartesi::HTIF_REASON_FIELD(tohost);
    const uint32_t tohost_data = cartesi::HTIF_DATA_FIELD(tohost);
    uint64_t data_length{};
    // Reason progress is an special case where it doesn't need to read cmio TX buffer
    if (tohost_cmd == cartesi::HTIF_YIELD_CMD_AUTOMATIC &&
        tohost_reason == cartesi::HTIF_YIELD_AUTOMATIC_REASON_PROGRESS) {
        data_length = sizeof(uint32_t);
        if (data != nullptr) { // Only actually read when data is not NULL
            if (data_length > *length) {
                throw std::invalid_argument{"data buffer length is too small"};
            }
            memcpy(data, &tohost_data, data_length);
        }
    } else {
        data_length = tohost_data;
        if (data != nullptr) { // Only actually read when data is not NULL
            if (data_length > *length) {
                throw std::invalid_argument{"data buffer length is too small"};
            }
            cpp_m->read_memory(cartesi::AR_CMIO_TX_BUFFER_START, data, data_length);
        }
    }
    if (cmd != nullptr) {
        *cmd = tohost_cmd;
    }
    if (reason != nullptr) {
        *reason = tohost_reason;
    }
    if (length != nullptr) {
        *length = data_length;
    }
    return cm_result_success();
} catch (...) {
    if (cmd != nullptr) {
        *cmd = 0;
    }
    if (reason != nullptr) {
        *reason = 0;
    }
    if (length != nullptr) {
        *length = 0;
    }
    return cm_result_failure();
}

cm_error cm_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->send_cmio_response(reason, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_m = convert_from_c(m);
    const cartesi::access_log::type cpp_log_type(log_type);
    const cartesi::access_log cpp_log = cpp_m->log_send_cmio_response(reason, data, length, cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log != nullptr) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_verify_send_cmio_response(const cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log, "log").value();
    const cartesi::machine_hash cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine_hash cpp_root_hash_after = convert_from_c(root_hash_after);
    if (m != nullptr) {
        const auto *cpp_m = convert_from_c(m);
        cpp_m->verify_send_cmio_response(reason, data, length, cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    } else {
        cartesi::machine::verify_send_cmio_response(reason, data, length, cpp_root_hash_before, cpp_log,
            cpp_root_hash_after);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
