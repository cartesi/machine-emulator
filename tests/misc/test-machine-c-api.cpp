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

#if defined(__clang__) && defined(__APPLE__)
#if !defined(__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#define __ENVIRONMENT_OS_VERSION_MIN_REQUIRED__ __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#endif
#endif

#define BOOST_TEST_MODULE Machine C API test // NOLINT(cppcoreguidelines-macro-usage)
#define BOOST_TEST_NO_OLD_TOOLS

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <boost/endian/conversion.hpp>
#include <boost/process.hpp>
#include <boost/test/included/unit_test.hpp>
#pragma GCC diagnostic pop

#define JSON_HAS_FILESYSTEM 0
#include <json.hpp>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include <machine-c-api.h>
#include <riscv-constants.h>
#include <uarch-constants.h>

#include "test-utils.h"
#include "uarch-solidity-compat.h"

// NOLINTBEGIN(cppcoreguidelines-avoid-do-while)

// NOLINTNEXTLINE
#define BOOST_AUTO_TEST_CASE_NOLINT(...) BOOST_AUTO_TEST_CASE(__VA_ARGS__)
// NOLINTNEXTLINE
#define BOOST_FIXTURE_TEST_CASE_NOLINT(...) BOOST_FIXTURE_TEST_CASE(__VA_ARGS__)

BOOST_AUTO_TEST_CASE_NOLINT(delete_machine_config_null_test) {
    BOOST_CHECK_NO_THROW(cm_delete_machine_config(nullptr));
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_access_log_null_test) {
    BOOST_CHECK_NO_THROW(cm_delete_access_log(nullptr));
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_machine_null_test) {
    BOOST_CHECK_NO_THROW(cm_delete_machine(nullptr));
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_proof_null_test) {
    BOOST_CHECK_NO_THROW(cm_delete_merkle_tree_proof(nullptr));
}

BOOST_AUTO_TEST_CASE_NOLINT(new_default_machine_config_basic_test) {
    const cm_machine_config *config = cm_new_default_machine_config();
    BOOST_TEST_CHECK(config != nullptr);
    cm_delete_machine_config(config);
}

BOOST_AUTO_TEST_CASE_NOLINT(get_default_machine_config_null_output_test) {
    int error_code = cm_get_default_config(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(get_default_machine_config_basic_test) {
    const cm_machine_config *config{};
    char *err_msg{};
    int error_code = cm_get_default_config(&config, &err_msg);
    BOOST_TEST_CHECK(config != nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    cm_delete_machine_config(config);
}

class default_machine_fixture {
public:
    default_machine_fixture() : _default_machine_config(cm_new_default_machine_config()) {}

    ~default_machine_fixture() {
        cm_delete_machine_config(_default_machine_config);
    }

    default_machine_fixture(const default_machine_fixture &other) = delete;
    default_machine_fixture(default_machine_fixture &&other) noexcept = delete;
    default_machine_fixture &operator=(const default_machine_fixture &other) = delete;
    default_machine_fixture &operator=(default_machine_fixture &&other) noexcept = delete;

protected:
    cm_machine_runtime_config _runtime_config{};
    cm_machine *_machine{};
    const cm_machine_config *_default_machine_config;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_unknown_dir_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_load("/unknown_dir", &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    BOOST_REQUIRE(result.find("unable to open '/unknown_dir/config.json' for reading") == 0);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_path_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_load(nullptr, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    BOOST_REQUIRE(result.find("unable to open '/config.json' for reading") == 0);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_config_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create(nullptr, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("invalid machine configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_rt_config_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create(_default_machine_config, nullptr, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_error_placeholder_test, default_machine_fixture) {
    int error_code = cm_create(_default_machine_config, nullptr, &_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_default_machine_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create(_default_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("RAM length cannot be zero");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

namespace {
char *new_cstr(const char *str) {
    auto size = strlen(str) + 1;
    auto *copy = new char[size];
    strncpy(copy, str, size);
    return copy;
}
} // namespace

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class incomplete_machine_fixture : public default_machine_fixture {
public:
    incomplete_machine_fixture() : _machine_config{} {
        _clone_machine_config(_default_machine_config, &_machine_config);
        _machine_config.ram.length = 1 << 20;
    }

    ~incomplete_machine_fixture() {
        _cleanup_machine_config(&_machine_config);
    }

    incomplete_machine_fixture(const incomplete_machine_fixture &other) = delete;
    incomplete_machine_fixture(incomplete_machine_fixture &&other) noexcept = delete;
    incomplete_machine_fixture &operator=(const incomplete_machine_fixture &other) = delete;
    incomplete_machine_fixture &operator=(incomplete_machine_fixture &&other) noexcept = delete;

protected:
    cm_machine_config _machine_config;

    static void _clone_machine_config(const cm_machine_config *source, cm_machine_config *target) {
        target->processor = source->processor;
        target->ram.length = source->ram.length;
        target->ram.image_filename = new_cstr(source->ram.image_filename);

        target->dtb.bootargs = new_cstr(source->dtb.bootargs);
        target->dtb.init = new_cstr(source->dtb.init);
        target->dtb.entrypoint = new_cstr(source->dtb.entrypoint);
        target->dtb.image_filename = new_cstr(source->dtb.image_filename);

        target->flash_drive.count = source->flash_drive.count;
        target->flash_drive.entry = new cm_memory_range_config[source->flash_drive.count]{};
        for (size_t i = 0; i < target->flash_drive.count; ++i) {
            target->flash_drive.entry[i] = source->flash_drive.entry[i];
            target->flash_drive.entry[i].image_filename = new_cstr(source->flash_drive.entry[i].image_filename);
        }

        target->tlb.image_filename = new_cstr(source->tlb.image_filename);
        target->clint = source->clint;
        target->plic = source->plic;
        target->htif = source->htif;
        target->cmio = source->cmio;

        target->uarch.processor = source->uarch.processor;
        target->uarch.ram.image_filename = new_cstr(source->uarch.ram.image_filename);
    }

    static void _cleanup_machine_config(cm_machine_config *config) {
        for (size_t i = 0; i < config->flash_drive.count; ++i) {
            delete[] config->flash_drive.entry[i].image_filename;
        }
        delete[] config->tlb.image_filename;
        delete[] config->flash_drive.entry;
        delete[] config->dtb.image_filename;
        delete[] config->dtb.bootargs;
        delete[] config->dtb.init;
        delete[] config->dtb.entrypoint;
        delete[] config->ram.image_filename;
        delete[] config->uarch.ram.image_filename;
    }

    void _setup_flash(std::list<cm_memory_range_config> &&config_list) {
        std::list<cm_memory_range_config> configs = std::move(config_list);
        _machine_config.flash_drive.count = configs.size();
        delete[] _machine_config.flash_drive.entry;
        _machine_config.flash_drive.entry = new cm_memory_range_config[configs.size()];

        for (auto [cfg_it, i] = std::tuple{configs.begin(), 0}; cfg_it != configs.end(); ++cfg_it, ++i) {
            std::ofstream flash_stream(cfg_it->image_filename);
            flash_stream << "aaaa";
            flash_stream.close();
            std::filesystem::resize_file(cfg_it->image_filename, cfg_it->length);

            _machine_config.flash_drive.entry[i].start = cfg_it->start;
            _machine_config.flash_drive.entry[i].length = cfg_it->length;
            _machine_config.flash_drive.entry[i].shared = cfg_it->shared;
            _machine_config.flash_drive.entry[i].image_filename = new_cstr(cfg_it->image_filename);
        }
    }

    void _setup_flash(const std::string &flash_path) {
        cm_memory_range_config flash_cfg = {0x80000000000000, 0x3c00000, true, flash_path.c_str()};
        _setup_flash({flash_cfg});
    }

    void _set_uarch_ram_image(const std::string &image_name) {
        delete[] _machine_config.uarch.ram.image_filename;
        _machine_config.uarch.ram.image_filename = new_cstr(image_name.c_str());
    }
};

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_machine_test, incomplete_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create(&_machine_config, &_runtime_config, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid new machine output");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

class machine_flash_fixture : public incomplete_machine_fixture {
public:
    machine_flash_fixture() {
        cm_memory_range_config flash1_cfg = {0x80000000000000, 0x3c00000, true, _flash1_path.c_str()};
        cm_memory_range_config flash2_cfg = {0x7ffffffffff000, 0x2000, true, _flash2_path.c_str()};
        _setup_flash({flash1_cfg, flash2_cfg});
    }

    ~machine_flash_fixture() {
        std::filesystem::remove(_flash1_path);
        std::filesystem::remove(_flash2_path);
    }

    machine_flash_fixture(const machine_flash_fixture &other) = delete;
    machine_flash_fixture(machine_flash_fixture &&other) noexcept = delete;
    machine_flash_fixture &operator=(const machine_flash_fixture &other) = delete;
    machine_flash_fixture &operator=(machine_flash_fixture &&other) noexcept = delete;

private:
    const std::string _flash1_path = "/tmp/flash1.bin";
    const std::string _flash2_path = "/tmp/flash2.bin";
};

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_pma_overlapping_test, machine_flash_fixture) {
    char *err_msg{};
    int error_code = cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("range of flash drive 1 overlaps with range of existing flash drive 0");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

class machine_flash_simple_fixture : public incomplete_machine_fixture {
public:
    machine_flash_simple_fixture() {
        _setup_flash(_flash_path);
    }

    ~machine_flash_simple_fixture() {
        std::filesystem::remove(_flash_path);
    }

    machine_flash_simple_fixture(const machine_flash_simple_fixture &other) = delete;
    machine_flash_simple_fixture(machine_flash_simple_fixture &&other) noexcept = delete;
    machine_flash_simple_fixture &operator=(const machine_flash_simple_fixture &other) = delete;
    machine_flash_simple_fixture &operator=(machine_flash_simple_fixture &&other) noexcept = delete;

protected:
    const std::string _flash_path = "/tmp/flash.bin";
};

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_alignment_test, machine_flash_simple_fixture) {
    _machine_config.flash_drive.entry[0].start -= 1;

    char *err_msg{};
    int error_code = cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("start of flash drive 0 (36028797018963967) must be aligned to page boundary of 4096 bytes");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_not_addressable_test, machine_flash_simple_fixture) {
    _machine_config.flash_drive.entry[0].start = 0x100000000000000 - 0x3c00000 + 4096;
    _machine_config.flash_drive.entry[0].length = 0x3c00000;

    char *err_msg{};
    int error_code = cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("range of flash drive 0 must use at most 56 bits to be addressable");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

class ordinary_machine_fixture : public incomplete_machine_fixture {
public:
    ordinary_machine_fixture() {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        char *err_msg{};
        cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);
    }
    ~ordinary_machine_fixture() {
        std::filesystem::remove_all(_machine_dir_path);
        cm_delete_machine(_machine);
    }

    ordinary_machine_fixture(const ordinary_machine_fixture &other) = delete;
    ordinary_machine_fixture(ordinary_machine_fixture &&other) noexcept = delete;
    ordinary_machine_fixture &operator=(const ordinary_machine_fixture &other) = delete;
    ordinary_machine_fixture &operator=(ordinary_machine_fixture &&other) noexcept = delete;

protected:
    std::string _machine_dir_path;
};

bool operator==(const cm_processor_config &lhs, const cm_processor_config &rhs) {
    for (int i = 0; i < CM_MACHINE_X_REG_COUNT; i++) {
        if (lhs.x[i] != rhs.x[i]) {
            return false;
        }
    }
    for (int i = 0; i < CM_MACHINE_F_REG_COUNT; i++) {
        if (lhs.f[i] != rhs.f[i]) {
            return false;
        }
    }
    return lhs.pc == rhs.pc && lhs.fcsr == rhs.fcsr && lhs.mvendorid == rhs.mvendorid && lhs.marchid == rhs.marchid &&
        lhs.mimpid == rhs.mimpid && lhs.mcycle == rhs.mcycle && lhs.icycleinstret == rhs.icycleinstret &&
        lhs.mstatus == rhs.mstatus && lhs.mtvec == rhs.mtvec && lhs.mscratch == rhs.mscratch && lhs.mepc == rhs.mepc &&
        lhs.mcause == rhs.mcause && lhs.mtval == rhs.mtval && lhs.misa == rhs.misa && lhs.mie == rhs.mie &&
        lhs.mip == rhs.mip && lhs.medeleg == rhs.medeleg && lhs.mideleg == rhs.mideleg &&
        lhs.mcounteren == rhs.mcounteren && lhs.menvcfg == rhs.menvcfg && lhs.stvec == rhs.stvec &&
        lhs.sscratch == rhs.sscratch && lhs.sepc == rhs.sepc && lhs.scause == rhs.scause && lhs.stval == rhs.stval &&
        lhs.satp == rhs.satp && lhs.scounteren == rhs.scounteren && lhs.senvcfg == rhs.senvcfg &&
        lhs.ilrsc == rhs.ilrsc && lhs.iflags == rhs.iflags && lhs.iunrep == rhs.iunrep;
}

bool operator==(const cm_ram_config &lhs, const cm_ram_config &rhs) {
    return (lhs.length == rhs.length && (strcmp(lhs.image_filename, rhs.image_filename) == 0));
}

bool operator==(const cm_dtb_config &lhs, const cm_dtb_config &rhs) {
    return ((strcmp(lhs.bootargs, rhs.bootargs) == 0) && (strcmp(lhs.init, rhs.init) == 0) &&
        (strcmp(lhs.entrypoint, rhs.entrypoint) == 0) && (strcmp(lhs.image_filename, rhs.image_filename) == 0));
}

bool operator==(const cm_tlb_config &lhs, const cm_tlb_config &rhs) {
    return (strcmp(lhs.image_filename, rhs.image_filename) == 0);
}

bool operator==(const cm_clint_config &lhs, const cm_clint_config &rhs) {
    return (lhs.mtimecmp == rhs.mtimecmp);
}

bool operator==(const cm_plic_config &lhs, const cm_plic_config &rhs) {
    return (lhs.girqpend == rhs.girqpend && lhs.girqsrvd == rhs.girqsrvd);
}

bool operator==(const cm_htif_config &lhs, const cm_htif_config &rhs) {
    return (lhs.fromhost == rhs.fromhost && lhs.tohost == rhs.tohost && lhs.console_getchar == rhs.console_getchar &&
        lhs.yield_manual == rhs.yield_manual && lhs.yield_automatic == rhs.yield_automatic);
}

bool operator==(const cm_machine_config &lhs, const cm_machine_config &rhs) {
    return ((lhs.processor == rhs.processor) && (lhs.dtb == rhs.dtb) && (lhs.ram == rhs.ram) && (lhs.tlb == rhs.tlb) &&
        (lhs.clint == rhs.clint) && (lhs.plic == rhs.plic) && (lhs.htif == rhs.htif));
}

std::ostream &boost_test_print_type(std::ostream &ostr, const cm_machine_config &rhs) {
    (void) rhs; // suppress 'unused param' warning
    ostr << "configs not equal\n";
    return ostr;
}

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class serialized_machine_fixture : public ordinary_machine_fixture {
public:
    serialized_machine_fixture() : _machine_config_path{std::filesystem::temp_directory_path() / "machine"} {
        char *err_msg{};
        int error_code = cm_store(_machine, _machine_config_path.string().c_str(), &err_msg);
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
        BOOST_CHECK_EQUAL(err_msg, nullptr);
    }

    virtual ~serialized_machine_fixture() {
        std::filesystem::remove_all(_machine_config_path.string());
    }

protected:
    std::filesystem::path _machine_config_path;

    auto _load_config() const {
        std::ifstream ifs(_config_dir(), std::ios::binary);
        BOOST_TEST((bool) ifs);
        auto j = nlohmann::json::parse(ifs);
        return std::make_pair(j["archive_version"], j["config"]);
    }

    void _store_config(const nlohmann::json &version, const nlohmann::json &config) const {
        std::ofstream ofs(_config_dir(), std::ios::binary);
        BOOST_TEST((bool) ofs);
        nlohmann::json j;
        j["archive_version"] = version;
        j["config"] = config;
        ofs << j;
    }

    std::string _config_dir() const {
        return (_machine_config_path / "config.json").string();
    }
};

// check that we process config version mismatch correctly
BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_invalid_config_version_test, serialized_machine_fixture) {
    auto [version, config] = _load_config();
    auto v = version.get<int>();
    _store_config(v + 1, config);

    std::stringstream expected_err;
    expected_err << "expected \"archive_version\" " << v << " (got " << v + 1 << ")";

    char *err_msg{};
    int error_code = cm_load(_machine_config_path.c_str(), &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(err_msg, expected_err.str().c_str());
    cm_delete_cstring(err_msg);
}

class store_file_fixture : public ordinary_machine_fixture {
public:
    store_file_fixture() : _broken_machine_path{(std::filesystem::temp_directory_path() / "machine").string()} {}

    ~store_file_fixture() {
        std::filesystem::remove_all(_broken_machine_path);
    }

    store_file_fixture(const store_file_fixture &other) = delete;
    store_file_fixture(store_file_fixture &&other) noexcept = delete;
    store_file_fixture &operator=(const store_file_fixture &other) = delete;
    store_file_fixture &operator=(store_file_fixture &&other) noexcept = delete;

protected:
    std::string _broken_machine_path;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(store_file_creation_test, store_file_fixture) {
    BOOST_REQUIRE(!std::filesystem::exists(_broken_machine_path));
    char *err_msg{};
    int error_code = cm_store(_machine, _broken_machine_path.c_str(), &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(std::filesystem::exists(_broken_machine_path));
}

// check that test config version is consistent with the generated config version
BOOST_FIXTURE_TEST_CASE_NOLINT(store_machine_config_version_test, store_file_fixture) {
    // store machine
    BOOST_REQUIRE(!std::filesystem::exists(_broken_machine_path));
    char *err_msg{};
    int error_code = cm_store(_machine, _broken_machine_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE(std::filesystem::exists(_broken_machine_path));

    // read stored config binary data
    std::ifstream ifs(_broken_machine_path + "/config.json", std::ios::out | std::fstream::binary);

    // check stored config version
    auto j = nlohmann::json::parse(ifs);
    BOOST_REQUIRE(j.contains("archive_version"));
    BOOST_REQUIRE(j["archive_version"].is_number_integer());
    BOOST_CHECK_EQUAL(j["archive_version"].get<int>(), 5);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_machine_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(nullptr, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    BOOST_CHECK_EQUAL(std::string("invalid machine"), std::string(err_msg));
    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_dir_path_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    std::string result = err_msg;
    BOOST_REQUIRE(result.find("error creating directory") == 0);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_error_placeholder_test, ordinary_machine_fixture) {
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_rtc_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_load(_machine_dir_path.c_str(), nullptr, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_machine_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_load(_machine_dir_path.c_str(), &_runtime_config, nullptr, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_error_placeholder_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    cm_machine *restored_machine{};
    error_code = cm_load(_machine_dir_path.c_str(), &_runtime_config, &restored_machine, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    cm_delete_machine(restored_machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(serde_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_machine *restored_machine{};
    error_code = cm_load(_machine_dir_path.c_str(), &_runtime_config, &restored_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_hash origin_hash{};
    error_code = cm_get_root_hash(_machine, &origin_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    cm_hash restored_hash{};
    error_code = cm_get_root_hash(restored_machine, &restored_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(0, memcmp(origin_hash, restored_hash, sizeof(cm_hash)));

    cm_delete_machine(restored_machine);
}

BOOST_AUTO_TEST_CASE_NOLINT(get_root_hash_null_machine_test) {
    cm_hash restored_hash;
    int error_code = cm_get_root_hash(nullptr, &restored_hash, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_null_test) {
    cm_delete_cstring(nullptr);
    cm_delete_memory_range_config(nullptr);
    cm_delete_machine_runtime_config(nullptr);
    cm_delete_machine_config(nullptr);
    cm_delete_machine(nullptr);
    cm_delete_access_log(nullptr);
    cm_delete_merkle_tree_proof(nullptr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_null_hash_test, ordinary_machine_fixture) {
    int error_code = cm_get_root_hash(_machine, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_null_error_placeholder_test, ordinary_machine_fixture) {
    cm_hash result_hash;
    int error_code = cm_get_root_hash(_machine, &result_hash, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_machine_hash_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_hash result_hash;
    int error_code = cm_get_root_hash(_machine, &result_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), result_hash, result_hash + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_proof_null_machine_test) {
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(nullptr, 0, 12, &proof, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_invalid_address_test, ordinary_machine_fixture) {
    char *err_msg{};
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(_machine, 1, 12, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("address not aligned to log2_size");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_invalid_log2_test, ordinary_machine_fixture) {
    char *err_msg{};
    cm_merkle_tree_proof *proof{};

    // log2_root_size = 64
    int error_code = cm_get_proof(_machine, 0, 65, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("invalid log2_size");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);

    // log2_word_size = 3
    error_code = cm_get_proof(_machine, 0, 2, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    result = err_msg;
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_inconsistent_tree_test, ordinary_machine_fixture) {
    char *err_msg{};
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(_machine, 0, 64, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_merkle_tree_proof(proof);

    // merkle tree is always consistent now as it updates on access

    error_code = cm_get_proof(_machine, 0, CM_TREE_LOG2_PAGE_SIZE, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_merkle_tree_proof(proof);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_null_proof_test, ordinary_machine_fixture) {
    int error_code = cm_get_proof(_machine, 0, 12, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_null_error_placeholder_test, ordinary_machine_fixture) {
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(_machine, 0, 12, &proof, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    cm_delete_merkle_tree_proof(proof);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_machine_hash_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_merkle_tree_proof *p{};
    int error_code = cm_get_proof(_machine, 0, 12, &p, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    auto verification = calculate_proof_root_hash(p);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), p->root_hash,
        p->root_hash + sizeof(cm_hash));
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), p->root_hash,
        p->root_hash + sizeof(cm_hash));
    BOOST_CHECK_EQUAL(p->log2_root_size, static_cast<size_t>(64));
    BOOST_CHECK_EQUAL(p->sibling_hashes.count, static_cast<size_t>(52));

    cm_delete_merkle_tree_proof(p);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_word_null_machine_test) {
    uint64_t word_value = 0;
    int error_code = cm_read_word(nullptr, 0x100, &word_value, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_invalid_address_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    char *err_msg{};
    int error_code = cm_read_word(_machine, 0xffffffff, &word_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("address not aligned");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_null_output_test, default_machine_fixture) {
    int error_code = cm_read_word(_machine, 0x100, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    int error_code = cm_read_word(_machine, cm_get_csr_address(CM_CSR_PC), &word_value, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(word_value, static_cast<uint64_t>(0x80000000));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_basic_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    char *err_msg{};
    int error_code = cm_read_word(_machine, cm_get_csr_address(CM_CSR_PC), &word_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(word_value, static_cast<uint64_t>(0x80000000));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_memory_null_machine_test) {
    std::array<uint8_t, sizeof(uint64_t)> rd{};
    int error_code = cm_read_memory(nullptr, 0x100, rd.data(), rd.size(), nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_memory_zero_data_size_test, ordinary_machine_fixture) {
    std::array<uint8_t, sizeof(uint64_t)> rd_origin{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    std::array<uint8_t, sizeof(uint64_t)> rd{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    char *err_msg{};
    int error_code = cm_read_memory(_machine, 0x100, rd.data(), 0, &err_msg);

    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL_COLLECTIONS(rd.begin(), rd.end(), rd_origin.begin(), rd_origin.end());
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_null_data_test, ordinary_machine_fixture) {
    int error_code = cm_read_memory(_machine, 0x80000000, nullptr, 1, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    error_code = cm_write_memory(_machine, 0x80000000, nullptr, 1, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_memory_null_machine_test) {
    std::array<uint8_t, sizeof(uint64_t)> wd{};
    int error_code = cm_write_memory(nullptr, 0x100, wd.data(), wd.size(), nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_null_error_placeholder_test, ordinary_machine_fixture) {
    int error_code = cm_write_memory(_machine, 0x80000000, nullptr, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_zero_data_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_write_memory(_machine, 0x80000000, nullptr, 0, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_null_data_size_mismatch_test, ordinary_machine_fixture) {
    int error_code = cm_write_memory(_machine, 0x80000000, nullptr, 1, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_read_word(_machine, address, &read_value, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_null_data_test, ordinary_machine_fixture) {
    int error_code = cm_read_virtual_memory(_machine, 0x80000000, nullptr, 1, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    error_code = cm_write_virtual_memory(_machine, 0x80000000, nullptr, 1, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_invalid_address_range_test, ordinary_machine_fixture) {
    uint64_t write_value = 0x1234;
    uint64_t address = 0x100;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("address range not entirely in memory PMA");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_word_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_word(_machine, address, &read_value, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    std::array<uint8_t, sizeof(uint64_t)> read_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    memcpy(&read_value, read_data.data(), read_data.size());
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_scattered_data, ordinary_machine_fixture) {
    uint16_t read_value = 0;
    uint16_t write_value = 0xdead;

    // we are going to write data on a page junction:
    // one byte at the end of the third page and one byte
    // at the beginning of the fourth
    uint64_t address = 0x80004000 - sizeof(write_value) / 2;

    std::array<uint8_t, sizeof(uint16_t)> write_data{};
    std::array<uint8_t, sizeof(uint16_t)> read_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    memcpy(&read_value, read_data.data(), read_data.size());
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_massive_test, ordinary_machine_fixture) {
    // writing somewhere in the middle of a page
    uint64_t address = 0x8000000F;
    // data occupies several pages and ends somewhere in the middle of a page
    constexpr size_t data_size = 12404;

    std::array<uint8_t, data_size> write_data{};
    std::array<uint8_t, data_size> read_data{};
    char *err_msg{};
    memset(write_data.data(), 0xda, data_size);

    int error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL_COLLECTIONS(write_data.begin(), write_data.end(), read_data.begin(), read_data.end());
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_virtual_memory_invalid_address_range_test, ordinary_machine_fixture) {
    uint64_t write_value = 0x1234;
    uint64_t address = 0x100;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("address range not entirely in memory PMA");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    std::array<uint8_t, sizeof(uint64_t)> read_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    memcpy(&read_value, read_data.data(), read_data.size());
    BOOST_CHECK_EQUAL(read_value, write_value);

    uint64_t paddr = 0;
    error_code = cm_translate_virtual_address(_machine, address, &paddr, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(paddr, address);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_scattered_data, ordinary_machine_fixture) {
    uint16_t read_value = 0;
    uint16_t write_value = 0xdead;

    // we are going to write data on a page junction:
    // one byte at the end of the third page and one byte
    // at the beginning of the fourth
    uint64_t address = 0x80004000 - sizeof(write_value) / 2;

    std::array<uint8_t, sizeof(uint16_t)> write_data{};
    std::array<uint8_t, sizeof(uint16_t)> read_data{};
    char *err_msg{};
    memcpy(write_data.data(), &write_value, write_data.size());

    int error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    memcpy(&read_value, read_data.data(), read_data.size());
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_massive_test, ordinary_machine_fixture) {
    // writing somewhere in the middle of a page
    uint64_t address = 0x8000000F;
    // data occupies several pages and ends somewhere in the middle of a page
    constexpr size_t data_size = 12404;

    std::array<uint8_t, data_size> write_data{};
    std::array<uint8_t, data_size> read_data{};
    char *err_msg{};
    memset(write_data.data(), 0xda, data_size);

    int error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL_COLLECTIONS(write_data.begin(), write_data.end(), read_data.begin(), read_data.end());
}

// NOLINTNEXTLINE
#define CHECK_READER_FAILS_ON_nullptr_MACHINE(T, reader_f)                                                             \
    BOOST_FIXTURE_TEST_CASE_NOLINT(read_##reader_f##_null_machine_test, ordinary_machine_fixture) {                    \
        T out{};                                                                                                       \
        int error_code = cm_read_##reader_f(nullptr, &out, nullptr);                                                   \
        BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);                                                    \
        error_code = cm_read_##reader_f(_machine, nullptr, nullptr);                                                   \
        BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);                                                    \
    }

// clang-format off
CHECK_READER_FAILS_ON_nullptr_MACHINE(uint64_t, mcycle)
CHECK_READER_FAILS_ON_nullptr_MACHINE(uint64_t, uarch_cycle)
CHECK_READER_FAILS_ON_nullptr_MACHINE(bool, iflags_Y)
CHECK_READER_FAILS_ON_nullptr_MACHINE(bool, iflags_X)
CHECK_READER_FAILS_ON_nullptr_MACHINE(bool, iflags_H)
// clang-format on

// NOLINTNEXTLINE
#define CHECK_WRITER_FAILS_ON_nullptr_MACHINE(writer_f)                                                                \
    BOOST_AUTO_TEST_CASE_NOLINT(write_##writer_f##_null_machine_test) {                                                \
        int error_code = cm_write_##writer_f(nullptr, 0x1, nullptr);                                                   \
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);                                                      \
    }

    // clang-format off
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mcycle)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(uarch_cycle)
// clang-format on

// NOLINTNEXTLINE
#define CHECK_REGISTER_READ_WRITE(F)                                                                                   \
    BOOST_FIXTURE_TEST_CASE_NOLINT(F##_read_write_test, ordinary_machine_fixture) {                                    \
        char *err_msg{};                                                                                               \
        uint64_t write_val = 0xad;                                                                                     \
        uint64_t read_val = 0;                                                                                         \
        int error_code = cm_write_##F(_machine, write_val, &err_msg);                                                  \
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);                                                                    \
        error_code = cm_read_##F(_machine, &read_val, &err_msg);                                                       \
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);                                                                    \
        BOOST_CHECK_EQUAL(err_msg, nullptr);                                                                           \
        BOOST_CHECK_EQUAL(write_val, read_val);                                                                        \
    }

    // clang-format off
CHECK_REGISTER_READ_WRITE(mcycle)
CHECK_REGISTER_READ_WRITE(uarch_cycle)
    // clang-format on

    BOOST_AUTO_TEST_CASE_NOLINT(set_iflags_y_null_machine_test) {
    int error_code = cm_set_iflags_Y(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(reset_iflags_y_null_machine_test) {
    int error_code = cm_reset_iflags_Y(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(packed_iflags_test) {
    uint64_t iflags = cm_packed_iflags(0, 0, 0, 0);
    BOOST_CHECK_EQUAL(0, iflags);
    iflags = cm_packed_iflags(1, 1, 1, 1);
    BOOST_CHECK_EQUAL(0xf, iflags);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(iflags_read_write_complex_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    char *err_msg{};

    int error_code = cm_read_csr(_machine, CM_CSR_IFLAGS, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x18));

    bool yflag{};
    bool xflag{};
    bool hflag{};
    error_code = cm_read_iflags_Y(_machine, &yflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(!yflag);
    error_code = cm_read_iflags_X(_machine, &xflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(!xflag);
    error_code = cm_read_iflags_H(_machine, &hflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(!hflag);

    error_code = cm_set_iflags_Y(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_csr(_machine, CM_CSR_IFLAGS, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x1a));

    error_code = cm_reset_iflags_Y(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_csr(_machine, CM_CSR_IFLAGS, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x18));
}
BOOST_FIXTURE_TEST_CASE_NOLINT(ids_read_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t vendorid{};
    uint64_t archid{};
    uint64_t impid{};

    int error_code = cm_read_csr(_machine, CM_CSR_MVENDORID, &vendorid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(vendorid, static_cast<uint64_t>(cartesi::MVENDORID_INIT));

    error_code = cm_read_csr(_machine, CM_CSR_MARCHID, &archid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(archid, static_cast<uint64_t>(cartesi::MARCHID_INIT));

    error_code = cm_read_csr(_machine, CM_CSR_MIMPID, &impid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(impid, static_cast<uint64_t>(cartesi::MIMPID_INIT));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_tohost_read_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_write_csr(_machine, CM_CSR_HTIF_TOHOST, 0x1111111111111111, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t htif_dev{};
    uint64_t htif_cmd{};
    uint64_t htif_data{};
    error_code = cm_read_csr(_machine, CM_CSR_HTIF_TOHOST_DEV, &htif_dev, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_dev, static_cast<uint64_t>(0x11));

    error_code = cm_read_csr(_machine, CM_CSR_HTIF_TOHOST_CMD, &htif_cmd, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_cmd, static_cast<uint64_t>(0x11));

    error_code = cm_read_csr(_machine, CM_CSR_HTIF_TOHOST_REASON, &htif_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x1111));

    error_code = cm_read_csr(_machine, CM_CSR_HTIF_TOHOST_DATA, &htif_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x11111111));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_fromhost_read_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t write_data = 0x0;
    int error_code = cm_write_csr(_machine, CM_CSR_HTIF_FROMHOST, write_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    write_data = 0x11111111;
    error_code = cm_write_csr(_machine, CM_CSR_HTIF_FROMHOST_DATA, write_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t htif_data{};
    error_code = cm_read_csr(_machine, CM_CSR_HTIF_FROMHOST_DATA, &htif_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x11111111));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_initial_config_null_machine_test) {
    const cm_machine_config *cfg{};
    int error_code = cm_get_initial_config(nullptr, &cfg, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_get_initial_config(_machine, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_null_error_placeholder_test, ordinary_machine_fixture) {
    const cm_machine_config *cfg{};
    int error_code = cm_get_initial_config(_machine, &cfg, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_machine_config(cfg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    const cm_machine_config *cfg{};
    int error_code = cm_get_initial_config(_machine, &cfg, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    // flash_drive comparison is not performed here
    // 'cause it's not a part of the initial config
    BOOST_CHECK_EQUAL(*cfg, _machine_config);
    cm_delete_machine_config(cfg);
}

BOOST_AUTO_TEST_CASE_NOLINT(verify_dirty_page_maps_null_machine_test) {
    bool result{};
    int error_code = cm_verify_dirty_page_maps(nullptr, &result, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_verify_dirty_page_maps(_machine, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_null_error_placeholder_test, ordinary_machine_fixture) {
    bool result{};
    int error_code = cm_verify_dirty_page_maps(_machine, &result, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK(result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_success_test, ordinary_machine_fixture) {
    char *err_msg{};
    bool result{};
    int error_code = cm_verify_dirty_page_maps(_machine, &result, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_flash_config_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid memory range configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

class flash_drive_machine_fixture : public machine_flash_simple_fixture {
public:
    flash_drive_machine_fixture() : _flash_config{}, _flash_data{"test data 1234567890"} {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        char *err_msg{};
        cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);

        size_t flash_size = 0x3c00000;
        std::string flash_file = "/tmp/data.bin";
        std::ofstream flash_stream(flash_file);
        flash_stream << _flash_data;
        flash_stream.close();
        std::filesystem::resize_file(flash_file, flash_size);

        _flash_config = {0x80000000000000, flash_size, true, new_cstr(flash_file.c_str())};
    }

    ~flash_drive_machine_fixture() {
        std::filesystem::remove_all(_machine_dir_path);
        cm_delete_machine(_machine);
        std::filesystem::remove(std::string{_flash_config.image_filename});
        delete[] _flash_config.image_filename;
    }

    flash_drive_machine_fixture(const flash_drive_machine_fixture &other) = delete;
    flash_drive_machine_fixture(flash_drive_machine_fixture &&other) noexcept = delete;
    flash_drive_machine_fixture &operator=(const flash_drive_machine_fixture &other) = delete;
    flash_drive_machine_fixture &operator=(flash_drive_machine_fixture &&other) noexcept = delete;

protected:
    cm_memory_range_config _flash_config;
    std::string _flash_data;
    std::string _machine_dir_path;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_flash_drive_test, flash_drive_machine_fixture) {
    char *err_msg{};
    const cm_machine_config *cfg{};
    int error_code = cm_get_initial_config(_machine, &cfg, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(*cfg, _machine_config);
    BOOST_CHECK_EQUAL(cfg->flash_drive.count, 1);
    cm_delete_machine_config(cfg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_machine_test, flash_drive_machine_fixture) {
    int error_code = cm_replace_memory_range(nullptr, &_flash_config, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_error_placeholder_test, flash_drive_machine_fixture) {
    int error_code = cm_replace_memory_range(_machine, &_flash_config, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_pma_test, flash_drive_machine_fixture) {
    _flash_config.start = 0x9000000000000;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_length_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x3c00;
    std::filesystem::resize_file(_flash_config.image_filename, _flash_config.length);

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_file_length_mismatch_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x3c00;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_zero_length_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x0;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_basic_test, flash_drive_machine_fixture) {
    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    std::array<uint8_t, 20> read_data{};
    error_code = cm_read_memory(_machine, _flash_config.start, read_data.data(), read_data.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string read_string{reinterpret_cast<char *>(read_data.data()), read_data.size()};
    BOOST_CHECK_EQUAL(_flash_data, read_string);
}

BOOST_AUTO_TEST_CASE_NOLINT(destroy_null_machine_test) {
    int error_code = cm_destroy(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(destroy_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_destroy(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
}

BOOST_AUTO_TEST_CASE_NOLINT(snapshot_null_machine_test) {
    int error_code = cm_snapshot(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(snapshot_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_snapshot(_machine, &err_msg);
    std::string result = err_msg;
    std::string origin("snapshot is not supported");
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_cstring(err_msg);
}

BOOST_AUTO_TEST_CASE_NOLINT(rollback_null_machine_test) {
    int error_code = cm_rollback(nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(rollback_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_rollback(_machine, &err_msg);
    std::string result = err_msg;
    std::string origin("rollback is not supported");
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_cstring(err_msg);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_x_null_machine_test) {
    uint64_t val{};
    int error_code = cm_read_x(nullptr, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_x_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_read_x(_machine, 4, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_x_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t val{};
    int error_code = cm_read_x(_machine, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_x_null_machine_test) {
    int error_code = cm_write_x(nullptr, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_x_null_error_placeholder_test, ordinary_machine_fixture) {
    int error_code = cm_write_x(_machine, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_x_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t x_origin = 42;
    uint64_t x_read{};
    int error_code = cm_write_x(_machine, 2, x_origin, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_x(_machine, 2, &x_read, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(x_origin, x_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x10), cm_get_x_address(2));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_f_null_machine_test) {
    uint64_t val{};
    int error_code = cm_read_f(nullptr, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_f_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_read_f(_machine, 4, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_f_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t val{};
    int error_code = cm_read_f(_machine, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_f_null_machine_test) {
    int error_code = cm_write_f(nullptr, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_f_null_error_placeholder_test, ordinary_machine_fixture) {
    int error_code = cm_write_f(_machine, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_f_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t f_origin = 42;
    uint64_t f_read{};
    int error_code = cm_write_f(_machine, 2, f_origin, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_f(_machine, 2, &f_read, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(f_origin, f_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x110), cm_get_f_address(2));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_uarch_x_null_machine_test) {
    uint64_t val{};
    int error_code = cm_read_uarch_x(nullptr, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_uarch_x_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_read_uarch_x(_machine, 4, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_uarch_x_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t val{};
    int error_code = cm_read_uarch_x(_machine, 4, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_uarch_x_null_machine_test) {
    int error_code = cm_write_uarch_x(nullptr, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_uarch_x_null_error_placeholder_test, ordinary_machine_fixture) {
    int error_code = cm_write_uarch_x(_machine, 4, 0, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_uarch_x_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t uarch_x_origin = 42;
    uint64_t uarch_x_read{};
    int error_code = cm_write_uarch_x(_machine, 2, uarch_x_origin, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_uarch_x(_machine, 2, &uarch_x_read, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(uarch_x_origin, uarch_x_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(cartesi::PMA_SHADOW_UARCH_STATE_START + 40), cm_get_uarch_x_address(2));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_csr_null_machine_test) {
    uint64_t val{};
    int error_code = cm_read_csr(nullptr, CM_CSR_MCYCLE, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_csr_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_read_csr(_machine, CM_CSR_MCYCLE, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_csr_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t val{};
    int error_code = cm_read_csr(_machine, CM_CSR_MCYCLE, &val, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_csr_null_machine_test) {
    int error_code = cm_write_csr(nullptr, CM_CSR_MCYCLE, 3, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_csr_null_error_placeholder_test, ordinary_machine_fixture) {
    uint64_t csr_origin = 42;
    uint64_t csr_read{};

    int error_code = cm_write_csr(_machine, CM_CSR_MCYCLE, csr_origin, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_read_csr(_machine, CM_CSR_MCYCLE, &csr_read, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(csr_origin, csr_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x200), cm_get_csr_address(CM_CSR_PC));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_csr_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t csr_origin = 42;
    uint64_t csr_read{};

    int error_code = cm_write_csr(_machine, CM_CSR_MCYCLE, csr_origin, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_csr(_machine, CM_CSR_MCYCLE, &csr_read, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(csr_origin, csr_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x200), cm_get_csr_address(CM_CSR_PC));
}

BOOST_AUTO_TEST_CASE_NOLINT(verify_merkle_tree_null_machine_test) {
    bool ret{};
    int error_code = cm_verify_merkle_tree(nullptr, &ret, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_null_output_test, ordinary_machine_fixture) {
    int error_code = cm_verify_merkle_tree(_machine, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_null_error_placeholder_test, ordinary_machine_fixture) {
    bool ret{};
    int error_code = cm_verify_merkle_tree(_machine, &ret, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK(ret);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    bool ret{};
    int error_code = cm_verify_merkle_tree(_machine, &ret, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(ret);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_log_null_log_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_verify_step_uarch_log(nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid access log");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

class access_log_machine_fixture : public incomplete_machine_fixture {
public:
    access_log_machine_fixture() {
        _log_type = {true, true, false};
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();

        uint32_t test_uarch_ram[] = {
            0x07b00513,                                                            //  li	a0,123
            (cartesi::uarch_ecall_functions::UARCH_ECALL_FN_HALT << 20) | 0x00893, // li a7,halt
            0x00000073,                                                            // ecall
        };
        std::ofstream of(_uarch_ram_path, std::ios::binary);
        of.write(static_cast<char *>(static_cast<void *>(&test_uarch_ram)), sizeof(test_uarch_ram));
        of.close();
        _set_uarch_ram_image(_uarch_ram_path);

        char *err_msg{};
        cm_create(&_machine_config, &_runtime_config, &_machine, &err_msg);
    }
    ~access_log_machine_fixture() {
        std::filesystem::remove_all(_machine_dir_path);
        std::filesystem::remove_all(_uarch_ram_path);
        cm_delete_machine(_machine);
    }

    access_log_machine_fixture(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture(access_log_machine_fixture &&other) noexcept = delete;
    access_log_machine_fixture &operator=(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture &operator=(access_log_machine_fixture &&other) noexcept = delete;

protected:
    std::string _machine_dir_path;
    const std::string _uarch_ram_path = "/tmp/test-uarch-ram.bin";
    cm_access_log *_access_log{};
    cm_access_log_type _log_type{};
};

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_log_null_error_placeholder_test, access_log_machine_fixture) {
    char *err_msg{};
    int error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_machine_test, access_log_machine_fixture) {
    int error_code = cm_log_step_uarch(nullptr, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_access_log_test, access_log_machine_fixture) {
    int error_code = cm_log_step_uarch(_machine, _log_type, false, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_error_placeholder_test, access_log_machine_fixture) {
    int error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_state_transition_null_hash0_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash1;
    int error_code = cm_verify_step_uarch_state_transition(nullptr, _access_log, &hash1, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid hash");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_state_transition_null_hash1_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    int error_code = cm_verify_step_uarch_state_transition(&hash0, _access_log, nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid hash");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_state_transition_null_access_log_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    cm_hash hash1;
    int error_code = cm_verify_step_uarch_state_transition(&hash0, nullptr, &hash1, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("invalid access log");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(log_step_uarch_complex_test_null_error_placeholder_test, access_log_machine_fixture) {
    cm_hash hash0;
    cm_hash hash1;

    int error_code = cm_get_root_hash(_machine, &hash0, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_get_root_hash(_machine, &hash1, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_verify_step_uarch_state_transition(&hash0, _access_log, &hash1, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    cm_delete_access_log(_access_log);
}

// sunda
BOOST_FIXTURE_TEST_CASE_NOLINT(log_step_uarch_until_halt, access_log_machine_fixture) {
    cm_hash hash0{};
    cm_hash hash1{};
    cm_hash hash2{};
    cm_hash hash3{};
    cm_hash hash4{};

    int error_code{};
    uint64_t cycle{};
    uint64_t halt{1};

    // at micro cycle 0
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // not halted
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(halt, 0);

    // get initial hash
    error_code = cm_get_root_hash(_machine, &hash0, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // step 1
    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash1, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch_state_transition(&hash0, _access_log, &hash1, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_access_log(_access_log);

    // step 2
    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash2, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch_state_transition(&hash1, _access_log, &hash2, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_access_log(_access_log);

    // step 3
    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash3, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch_state_transition(&hash2, _access_log, &hash3, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_access_log(_access_log);
    // step 4
    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    error_code = cm_verify_step_uarch_log(_access_log, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash4, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch_state_transition(&hash3, _access_log, &hash4, false, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_access_log(_access_log);

    // at micro cycle 4
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 3);

    // halted
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(halt, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_complex_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    cm_hash hash1;

    int error_code = cm_get_root_hash(_machine, &hash0, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_verify_step_uarch_log(_access_log, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_get_root_hash(_machine, &hash1, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_verify_step_uarch_state_transition(&hash0, _access_log, &hash1, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_hash_test, access_log_machine_fixture) {
    char *err_msg{};

    int error_code = cm_log_step_uarch(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_hash hash1;
    error_code = cm_get_root_hash(_machine, &hash1, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash1, hash1 + sizeof(cm_hash));

    cm_delete_access_log(_access_log);
}

BOOST_AUTO_TEST_CASE_NOLINT(machine_run_null_machine_test) {
    CM_BREAK_REASON break_reason{};
    int error_code = cm_run(nullptr, 1000, &break_reason, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    BOOST_CHECK_EQUAL(break_reason, CM_BREAK_REASON_FAILED);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_null_error_placeholder_test, ordinary_machine_fixture) {
    CM_BREAK_REASON break_reason{};
    int error_code = cm_run(_machine, 1000, &break_reason, nullptr);
    BOOST_CHECK_EQUAL(break_reason, CM_BREAK_REASON_REACHED_TARGET_MCYCLE);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_1000_cycle_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_run(_machine, 1000, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t read_mcycle{};
    error_code = cm_read_mcycle(_machine, &read_mcycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_mcycle, static_cast<uint64_t>(1000));

    cm_hash hash_1000;
    error_code = cm_get_root_hash(_machine, &hash_1000, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_1000, hash_1000 + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_to_past_test, ordinary_machine_fixture) {
    uint64_t cycle_num = 1000;
    uint64_t cycle_num_to_past = 100;

    char *err_msg{};
    int error_code = cm_run(_machine, cycle_num, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t read_mcycle{};
    error_code = cm_read_mcycle(_machine, &read_mcycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_mcycle, cycle_num);

    error_code = cm_run(_machine, cycle_num_to_past, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("mcycle is past");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_cstring(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_long_cycle_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_run(_machine, 600000, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t read_mcycle{};
    error_code = cm_read_mcycle(_machine, &read_mcycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_mcycle, static_cast<uint64_t>(600000));

    cm_hash hash_end;
    error_code = cm_get_root_hash(_machine, &hash_end, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_end, hash_end + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(machine_run_uarch_null_machine_test) {
    auto status{CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE};
    int error_code = cm_run_uarch(nullptr, 1000, &status, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_uarch_advance_one_cycle, access_log_machine_fixture) {
    char *err_msg{};

    // ensure that uarch cycle is 0
    uint64_t cycle{};
    int error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // advance one uarch cycle
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, 1, &status, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE);

    // confirm uarch cycle was incremented
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(cycle, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_uarch_advance_until_halt, access_log_machine_fixture) {
    char *err_msg{};
    // ensure that uarch cycle is 0
    uint64_t cycle{};
    int error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // ensure not halted
    uint64_t halt{1};
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(halt, 0);

    // save initial hash
    cm_hash initial_hash{};
    cm_get_root_hash(_machine, &initial_hash, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // advance one micro cycle
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, 1, &status, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE);

    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 1);

    // hash after one step should be different from the initial hash
    cm_hash one_cycle_hash{};
    cm_get_root_hash(_machine, &one_cycle_hash, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK(0 != memcmp(initial_hash, one_cycle_hash, sizeof(cm_hash)));

    // advance more micro cycles past the point where the program halts (see hard-coded micro code in test fixture )
    error_code = cm_run_uarch(_machine, 100, &status, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    // assert result status reports
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // confirm uarch cycle advanced
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(cycle, 3);

    // assert halt flag is set
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(halt, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_reset_uarch, ordinary_machine_fixture) {
    char *err_msg{};
    // ensure that uarch cycle is 0
    uint64_t halt_cycle{};
    uint64_t cycle{};
    int error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, &err_msg);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // ensure not halted
    uint64_t halt{1};
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(halt, 0);

    // save initial uarch ram
    std::vector<unsigned char> initial_uarch_ram(cartesi::UARCH_RAM_LENGTH);
    error_code = cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, initial_uarch_ram.data(),
        initial_uarch_ram.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    // run until halt
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, -1, &status, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // confirm if halt flag is set
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(halt, 1);

    // save halt cycle
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &halt_cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE(halt_cycle > 0);

    // try run_uarch past the halted cycle
    error_code = cm_run_uarch(_machine, halt_cycle + 1, &status, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // should stay at halt cycle
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_CYCLE, &cycle, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, halt_cycle);

    // change the uarch ram in order to confirm if reset will restore it to the initial value
    std::array<uint8_t, 8> random_bytes{1, 2, 3, 4, 5, 6, 7, 8};
    error_code =
        cm_write_memory(_machine, cartesi::PMA_UARCH_RAM_START, random_bytes.data(), random_bytes.size(), nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // grab the modified ram bytes
    std::vector<unsigned char> modified_uarch_ram(cartesi::PMA_UARCH_RAM_LENGTH);
    error_code = cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, modified_uarch_ram.data(),
        modified_uarch_ram.size(), nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // ensure that modified ram is different from the one initially saved
    BOOST_REQUIRE(initial_uarch_ram != modified_uarch_ram);

    // reset state
    error_code = cm_reset_uarch(_machine, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    // halt flag should be cleared
    error_code = cm_read_csr(_machine, CM_CSR_UARCH_HALT_FLAG, &halt, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(halt, 0);

    // grab the ram after reset
    std::vector<unsigned char> reset_uarch_ram(cartesi::UARCH_RAM_LENGTH);
    error_code = cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, reset_uarch_ram.data(),
        reset_uarch_ram.size(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    // confirm ram was restored to initial state
    BOOST_REQUIRE(initial_uarch_ram == reset_uarch_ram);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_verify_merkle_tree_root_updates_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_hash start_hash;
    int error_code = cm_get_root_hash(_machine, &start_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_hash, start_hash + sizeof(cm_hash));

    error_code = cm_run(_machine, 1000, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_hash end_hash;
    error_code = cm_get_root_hash(_machine, &end_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_hash, end_hash + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_verify_merkle_tree_proof_updates_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_merkle_tree_proof *start_proof{};
    int error_code = cm_get_proof(_machine, 0, 12, &start_proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    auto verification = calculate_proof_root_hash(start_proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_proof->root_hash,
        start_proof->root_hash + sizeof(cm_hash));
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_proof->root_hash,
        start_proof->root_hash + sizeof(cm_hash));
    cm_delete_merkle_tree_proof(start_proof);

    error_code = cm_run(_machine, 1000, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_merkle_tree_proof *end_proof{};
    error_code = cm_get_proof(_machine, 0, 12, &end_proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    verification = calculate_proof_root_hash(end_proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_proof->root_hash,
        end_proof->root_hash + sizeof(cm_hash));
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_proof->root_hash,
        end_proof->root_hash + sizeof(cm_hash));
    cm_delete_merkle_tree_proof(end_proof);
}

BOOST_AUTO_TEST_CASE_NOLINT(uarch_solidity_compatibility_layer) {
    using namespace cartesi;
    BOOST_CHECK_EQUAL(UINT16_MAX, 65535);
    BOOST_CHECK_EQUAL(UINT32_MAX, 4294967295U);
    BOOST_CHECK_EQUAL(UINT64_MAX, 18446744073709551615ULL);
    BOOST_CHECK_EQUAL(INT16_MAX, 32767);
    BOOST_CHECK_EQUAL(INT32_MAX, 2147483647);
    BOOST_CHECK_EQUAL(INT64_MAX, 9223372036854775807LL);
    BOOST_CHECK_EQUAL(INT16_MIN, -32768);
    BOOST_CHECK_EQUAL(INT32_MIN, -INT32_MAX - 1);
    BOOST_CHECK_EQUAL(INT64_MIN, -INT64_MAX - 1);

    BOOST_CHECK_EQUAL(uint64ToInt32(1), 1);
    BOOST_CHECK_EQUAL(uint64ToInt32(0xffffffffULL), -1);
    BOOST_CHECK_EQUAL(uint64ToInt32(0xffffffffULL << 31), INT32_MIN);
    BOOST_CHECK_EQUAL(uint64ToInt32(0xffffffffULL << 32), 0);

    BOOST_CHECK_EQUAL(uint64AddInt32(2, -1), 1);
    BOOST_CHECK_EQUAL(uint64AddInt32(0, -1), UINT64_MAX);
    BOOST_CHECK_EQUAL(uint64AddInt32(UINT64_MAX, 1), 0);

    BOOST_CHECK_EQUAL(uint64SubUint64(1, 1), 0);
    BOOST_CHECK_EQUAL(uint64SubUint64(0, 1), UINT64_MAX);

    BOOST_CHECK_EQUAL(uint64AddUint64(0, 1), 1);
    BOOST_CHECK_EQUAL(uint64AddUint64(UINT64_MAX, 1), 0);

    BOOST_CHECK_EQUAL(uint64ShiftRight(0, 0), 0);
    BOOST_CHECK_EQUAL(uint64ShiftRight(0, 1), 0);
    BOOST_CHECK_EQUAL(uint64ShiftRight(4, 1), 2);
    BOOST_CHECK_EQUAL(uint64ShiftRight(4, 2), 1);
    BOOST_CHECK_EQUAL(uint64ShiftRight(4, 3), 0);
    BOOST_CHECK_EQUAL(uint64ShiftRight(UINT64_MAX, 63), 1);

    BOOST_CHECK_EQUAL(uint64ShiftLeft(0, 0), 0);
    BOOST_CHECK_EQUAL(uint64ShiftLeft(0, 1), 0);
    BOOST_CHECK_EQUAL(uint64ShiftLeft(4, 1), 8);
    BOOST_CHECK_EQUAL(uint64ShiftLeft(4, 2), 16);
    BOOST_CHECK_EQUAL(uint64ShiftLeft(UINT64_MAX, 63), 1ULL << 63);

    BOOST_CHECK_EQUAL(int64ShiftRight(0, 0), 0);
    BOOST_CHECK_EQUAL(int64ShiftRight(0, 1), 0);
    BOOST_CHECK_EQUAL(int64ShiftRight(4, 1), 2);
    BOOST_CHECK_EQUAL(int64ShiftRight(4, 2), 1);
    BOOST_CHECK_EQUAL(int64ShiftRight(4, 3), 0);
    BOOST_CHECK_EQUAL(int64ShiftRight(INT64_MAX, 62), 1);
    BOOST_CHECK_EQUAL(int64ShiftRight(INT64_MAX, 63), 0);
    BOOST_CHECK_EQUAL(int64ShiftRight(-1, 1), -1);
    BOOST_CHECK_EQUAL(int64ShiftRight(-4, 1), -2);
    BOOST_CHECK_EQUAL(int64ShiftRight(INT64_MIN, 62), -2);
    BOOST_CHECK_EQUAL(int64ShiftRight(INT64_MIN, 63), -1);

    BOOST_CHECK_EQUAL(int64AddInt64(0, 0), 0);
    BOOST_CHECK_EQUAL(int64AddInt64(0, 1), 1);
    BOOST_CHECK_EQUAL(int64AddInt64(0, -1), -1);
    BOOST_CHECK_EQUAL(int64AddInt64(-1, 0), -1);
    BOOST_CHECK_EQUAL(int64AddInt64(INT64_MAX, 1), INT64_MIN);
    BOOST_CHECK_EQUAL(int64AddInt64(INT64_MAX, INT64_MAX), -2);

    BOOST_CHECK_EQUAL(uint32ShiftRight(0, 0), 0);
    BOOST_CHECK_EQUAL(uint32ShiftRight(0, 1), 0);
    BOOST_CHECK_EQUAL(uint32ShiftRight(4, 1), 2);
    BOOST_CHECK_EQUAL(uint32ShiftRight(4, 2), 1);
    BOOST_CHECK_EQUAL(uint32ShiftRight(4, 3), 0);
    BOOST_CHECK_EQUAL(uint32ShiftRight(UINT32_MAX, 31), 1);

    BOOST_CHECK_EQUAL(uint32ShiftLeft(0, 0), 0);
    BOOST_CHECK_EQUAL(uint32ShiftLeft(0, 1), 0);
    BOOST_CHECK_EQUAL(uint32ShiftLeft(4, 1), 8);
    BOOST_CHECK_EQUAL(uint32ShiftLeft(4, 2), 16);
    BOOST_CHECK_EQUAL(uint32ShiftLeft(4, 3), 32);
    BOOST_CHECK_EQUAL(uint32ShiftLeft(UINT32_MAX, 31), 0x80000000UL);

    BOOST_CHECK_EQUAL(int32ToUint64(1), 1);
    BOOST_CHECK_EQUAL(int32ToUint64(INT32_MAX), INT32_MAX);
    BOOST_CHECK_EQUAL(int32ToUint64(INT32_MIN), 0xffffffff80000000ULL);

    BOOST_CHECK_EQUAL(int32ShiftRight(0, 0), 0);
    BOOST_CHECK_EQUAL(int32ShiftRight(0, 1), 0);
    BOOST_CHECK_EQUAL(int32ShiftRight(4, 1), 2);
    BOOST_CHECK_EQUAL(int32ShiftRight(4, 2), 1);
    BOOST_CHECK_EQUAL(int32ShiftRight(4, 3), 0);
    BOOST_CHECK_EQUAL(int32ShiftRight(INT32_MAX, 30), 1);
    BOOST_CHECK_EQUAL(int32ShiftRight(INT32_MAX, 31), 0);
    BOOST_CHECK_EQUAL(int32ShiftRight(-1, 1), -1);
    BOOST_CHECK_EQUAL(int32ShiftRight(-4, 1), -2);
    BOOST_CHECK_EQUAL(int32ShiftRight(INT32_MIN, 30), -2);
    BOOST_CHECK_EQUAL(int32ShiftRight(INT32_MIN, 31), -1);

    BOOST_CHECK_EQUAL(int32AddInt32(0, 0), 0);
    BOOST_CHECK_EQUAL(int32AddInt32(0, 1), 1);
    BOOST_CHECK_EQUAL(int32AddInt32(0, -1), -1);
    BOOST_CHECK_EQUAL(int32AddInt32(-1, 0), -1);
    BOOST_CHECK_EQUAL(int32AddInt32(INT32_MAX, 1), INT32_MIN);
    BOOST_CHECK_EQUAL(int32AddInt32(INT32_MAX, INT32_MAX), -2);

    BOOST_CHECK_EQUAL(int32SubInt32(1, 1), 0);
    BOOST_CHECK_EQUAL(int32SubInt32(1, 0), 1);
    BOOST_CHECK_EQUAL(int32SubInt32(0, 1), -1);
    BOOST_CHECK_EQUAL(int32SubInt32(-1, -1), 0);
    BOOST_CHECK_EQUAL(int32SubInt32(INT32_MIN, INT32_MAX), 1);
    BOOST_CHECK_EQUAL(int32SubInt32(INT32_MAX, INT32_MIN), -1);

    BOOST_CHECK_EQUAL(int16ToUint64(1), 1);
    BOOST_CHECK_EQUAL(int16ToUint64(INT16_MAX), INT16_MAX);
    BOOST_CHECK_EQUAL(int16ToUint64(INT16_MIN), 0xffffffffffff8000ULL);

    BOOST_CHECK_EQUAL(int8ToUint64(int8(1)), 1);
    BOOST_CHECK_EQUAL(int8ToUint64(int8(127)), 127);
    BOOST_CHECK_EQUAL(int8ToUint64(int8(-128)), 0xffffffffffffff80ULL);
}
// NOLINTEND(cppcoreguidelines-avoid-do-while)
