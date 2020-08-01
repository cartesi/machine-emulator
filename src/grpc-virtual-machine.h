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

#ifndef GRPC_VIRTUAL_MACHINE
#define GRPC_VIRTUAL_MACHINE

#include <cstdint>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <grpc++/grpc++.h>
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

#include "i-virtual-machine.h"

using CartesiMachine::Machine;

namespace cartesi {

/// \class grpc_virtual_machine
/// \brief GRPC implementation of the i_virtual_machine interface
class grpc_virtual_machine : public i_virtual_machine {
    std::unique_ptr<Machine::Stub> m_stub;
public:
    grpc_virtual_machine(const std::string &address, const std::string &dir);
    grpc_virtual_machine(const std::string &address, const machine_config &c);
    ~grpc_virtual_machine();

private:
    void create_machine(const std::string &dir);
    void create_machine(const machine_config &c);
    machine_config do_get_initial_config(void) override;
    void do_run(uint64_t mcycle_end) override;
    void do_store(const std::string &dir) override;
    uint64_t do_read_csr(csr r) override;
    void do_write_csr(csr w, uint64_t val) override;
    uint64_t do_get_csr_address(csr w) override;
    uint64_t do_read_x(int i) override;
    void do_write_x(int i, uint64_t val) override;
    uint64_t do_get_x_address(int i) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) override;
    void do_write_memory(uint64_t address, const unsigned char *data, size_t length) override;
    void do_get_root_hash(hash_type &hash) override;
    void do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) override;
    void do_replace_flash_drive(const flash_drive_config &new_flash) override;
    access_log do_step(const access_log::type &log_type, bool /*one_based = false*/) override;
    void do_shutdown() override;
    void do_snapshot() override;
    void do_rollback() override;
    bool do_verify_dirty_page_maps(void) override;
    void do_dump_pmas(void) override;
    bool do_read_word(uint64_t word_address, uint64_t &word_value) override;
    bool do_verify_merkle_tree(void) override;
    bool do_update_merkle_tree(void) override;
};

} // namespace cartesi

#endif
