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

/// \file
/// \brief Differential fuzz harness for step verification.
///
/// Creates a machine with fuzzed state, stores it, clones it into 4 copies,
/// and runs each through a different execution path. All 4 must produce the
/// same root hash after each big-machine step.
///
/// The four paths are:
///
///   1. cm_run()           — fast interpreter (ground truth)
///   2. cm_run_uarch()     — uarch execution + reset
///   3. cm_log_step_uarch() + cm_verify_step_uarch() — uarch cycle-by-cycle
///                           with fraud proof verification at each micro-step
///   4. cm_log_step() + cm_verify_step() — page-based fraud proof
///
/// The fuzz input format is identical to fuzz-interpret (see fuzz-common.h).

#include "fuzz-common.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>

/// \brief RAII wrapper for a temporary directory tree.
/// Creates a base directory; subdirectories are created by the caller.
/// Removes everything on destruction.
struct tmp_dir_tree {
    std::string base;

    tmp_dir_tree() {
        char tmpl[] = "/tmp/fuzz-step-XXXXXX";
        if (!mkdtemp(tmpl)) {
            base.clear();
        } else {
            base = tmpl;
        }
    }

    ~tmp_dir_tree() {
        if (!base.empty()) {
            std::filesystem::remove_all(base);
        }
    }

    tmp_dir_tree(const tmp_dir_tree &) = delete;
    tmp_dir_tree &operator=(const tmp_dir_tree &) = delete;

    /// Returns a subdirectory path. Does NOT create it (cm_store/cm_clone_stored will).
    std::string sub(const char *name) const {
        return base + "/" + name;
    }

    explicit operator bool() const {
        return !base.empty();
    }
};

/// \brief Abort with a message (signals a bug to libFuzzer).
[[noreturn]] static void fuzz_abort(const char *msg) {
    fprintf(stderr, "FUZZ BUG: %s\n", msg);
    abort();
}

// Entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    fuzz_reader r{data, size};

    // Read register state and create machine with fuzzed state
    cartesi::registers_state regs{};
    bool enable_vm = false;
    fuzz_read_registers(r, regs, enable_vm);
    cm_machine *m0 = fuzz_create_machine(r, regs, enable_vm);
    if (!m0) {
        return 0;
    }

    // Set up temporary directory tree for storage
    tmp_dir_tree tmpdir;
    if (!tmpdir) {
        cm_delete(m0);
        return 0;
    }

    const auto store_dir = tmpdir.sub("base");
    const auto dir2 = tmpdir.sub("m2");
    const auto dir3 = tmpdir.sub("m3");
    const auto dir4 = tmpdir.sub("m4");
    const auto log_file = tmpdir.sub("step.log");

    // Store machine state to disk so we can clone it.
    // SHARING_ALL is required because the machine was created in-memory (no backing files).
    // This does not modify m0's in-memory state.
    if (cm_store(m0, store_dir.c_str(), CM_SHARING_ALL) != CM_ERROR_OK) {
        cm_delete(m0);
        return 0;
    }

    // Clone to 3 directories; reuse m0 as path 1
    if (cm_clone_stored(nullptr, store_dir.c_str(), dir2.c_str()) != CM_ERROR_OK ||
        cm_clone_stored(nullptr, store_dir.c_str(), dir3.c_str()) != CM_ERROR_OK ||
        cm_clone_stored(nullptr, store_dir.c_str(), dir4.c_str()) != CM_ERROR_OK) {
        cm_delete(m0);
        return 0;
    }

    // Reuse original as path 1; load 3 independent clones for paths 2-4
    cm_machine *m1 = m0;
    cm_machine *m2 = nullptr;
    cm_machine *m3 = nullptr;
    cm_machine *m4 = nullptr;
    if (cm_load_new(dir2.c_str(), nullptr, CM_SHARING_NONE, &m2) != CM_ERROR_OK ||
        cm_load_new(dir3.c_str(), nullptr, CM_SHARING_NONE, &m3) != CM_ERROR_OK ||
        cm_load_new(dir4.c_str(), nullptr, CM_SHARING_NONE, &m4) != CM_ERROR_OK) {
        cm_delete(m1);
        cm_delete(m2);
        cm_delete(m3);
        cm_delete(m4);
        return 0;
    }

    // Get initial mcycle
    uint64_t mcycle = 0;
    cm_read_reg(m1, CM_REG_MCYCLE, &mcycle);
    const uint64_t mcycle_end = mcycle + MAX_MCYCLE;

    for (uint64_t target = mcycle + 1; target <= mcycle_end; target++) {
        // Path 1: fast interpreter — one big-machine step
        cm_break_reason br1{};
        cm_run(m1, target, &br1);

        // Path 2: uarch run to completion + reset
        cm_uarch_break_reason ubr2{};
        cm_run_uarch(m2, CM_UARCH_CYCLE_MAX, &ubr2);
        cm_reset_uarch(m2);

        // Path 3: uarch cycle-by-cycle with log + verify at each micro-step
        for (;;) {
            cm_hash hb{};
            cm_hash ha{};
            cm_get_root_hash(m3, &hb);
            const char *log = nullptr;
            if (cm_log_step_uarch(m3, CM_ACCESS_LOG_TYPE_LARGE_DATA, &log) != CM_ERROR_OK) {
                fuzz_abort("cm_log_step_uarch failed");
            }
            cm_get_root_hash(m3, &ha);
            if (cm_verify_step_uarch(m3, &hb, log, &ha) != CM_ERROR_OK) {
                fuzz_abort("cm_verify_step_uarch failed");
            }
            uint64_t halt = 0;
            cm_read_reg(m3, CM_REG_UARCH_HALT_FLAG, &halt);
            if (halt) {
                break;
            }
            uint64_t ucycle = 0;
            cm_read_reg(m3, CM_REG_UARCH_CYCLE, &ucycle);
            if (ucycle >= CM_UARCH_CYCLE_MAX) {
                break;
            }
        }
        // Reset uarch with log + verify
        {
            cm_hash hb{};
            cm_hash ha{};
            cm_get_root_hash(m3, &hb);
            const char *log = nullptr;
            if (cm_log_reset_uarch(m3, CM_ACCESS_LOG_TYPE_LARGE_DATA, &log) != CM_ERROR_OK) {
                fuzz_abort("cm_log_reset_uarch failed");
            }
            cm_get_root_hash(m3, &ha);
            if (cm_verify_reset_uarch(m3, &hb, log, &ha) != CM_ERROR_OK) {
                fuzz_abort("cm_verify_reset_uarch failed");
            }
        }

        // Path 4: page-based fraud proof — log_step + verify_step
        {
            cm_hash hb{};
            cm_hash ha{};
            cm_get_root_hash(m4, &hb);
            cm_break_reason br4{};
            if (cm_log_step(m4, 1, log_file.c_str(), &br4) != CM_ERROR_OK) {
                fuzz_abort("cm_log_step failed");
            }
            cm_get_root_hash(m4, &ha);
            cm_break_reason br4v{};
            if (cm_verify_step(&hb, log_file.c_str(), 1, &ha, &br4v) != CM_ERROR_OK) {
                fuzz_abort("cm_verify_step failed");
            }
            // Remove log file so the next iteration can create it
            std::filesystem::remove(log_file);
        }

        // Compare root hashes across all 4 paths
        cm_hash h1{};
        cm_hash h2{};
        cm_hash h3{};
        cm_hash h4{};
        cm_get_root_hash(m1, &h1);
        cm_get_root_hash(m2, &h2);
        cm_get_root_hash(m3, &h3);
        cm_get_root_hash(m4, &h4);

        if (memcmp(&h1, &h2, sizeof(cm_hash)) != 0) {
            fuzz_abort("hash mismatch: cm_run vs cm_run_uarch");
        }
        if (memcmp(&h1, &h3, sizeof(cm_hash)) != 0) {
            fuzz_abort("hash mismatch: cm_run vs uarch cycle-by-cycle log+verify");
        }
        if (memcmp(&h1, &h4, sizeof(cm_hash)) != 0) {
            fuzz_abort("hash mismatch: cm_run vs cm_log_step+cm_verify_step");
        }

        // Stop if the machine halted
        if (br1 == CM_BREAK_REASON_HALTED) {
            break;
        }
    }

    cm_delete(m1);
    cm_delete(m2);
    cm_delete(m3);
    cm_delete(m4);
    return 0;
}
