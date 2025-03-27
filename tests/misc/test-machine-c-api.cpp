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
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/endian/conversion.hpp>
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

BOOST_AUTO_TEST_CASE_NOLINT(delete_machine_null_test) {
    BOOST_CHECK_NO_THROW(cm_delete(nullptr));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_default_machine_config_basic_test) {
    const char *config{};
    cm_error error_code = cm_get_default_config(nullptr, &config);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_TEST_CHECK(config != nullptr);
}

class default_machine_fixture {
public:
    default_machine_fixture() {
        const char *config{};
        cm_get_default_config(nullptr, &config);
        _default_machine_config = config;
    }

    ~default_machine_fixture() {}

    default_machine_fixture(const default_machine_fixture &other) = delete;
    default_machine_fixture(default_machine_fixture &&other) noexcept = delete;
    default_machine_fixture &operator=(const default_machine_fixture &other) = delete;
    default_machine_fixture &operator=(default_machine_fixture &&other) noexcept = delete;

protected:
    cm_machine *_machine{};
    std::string _default_machine_config{};
};

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_unknown_dir_test, default_machine_fixture) {
    cm_error error_code = cm_load_new("/unknown_dir", nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_SYSTEM_ERROR);

    std::string result = cm_get_last_error_message();
    BOOST_REQUIRE(result.find("unable to open '/unknown_dir/config.json' for reading") == 0);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_path_test, default_machine_fixture) {
    cm_error error_code = cm_load_new(nullptr, nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    BOOST_REQUIRE(result.find("invalid dir") == 0);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_config_test, default_machine_fixture) {
    cm_error error_code = cm_create_new(nullptr, nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = cm_get_last_error_message();
    std::string origin("invalid machine configuration");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_default_machine_test, default_machine_fixture) {
    cm_error error_code = cm_create_new(_default_machine_config.c_str(), nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string("RAM length cannot be zero"));
}

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class incomplete_machine_fixture : public default_machine_fixture {
public:
    incomplete_machine_fixture() : _machine_config{} {
        const char *config{};
        cm_get_default_config(nullptr, &config);
        _machine_config = nlohmann::json::parse(config);
        _machine_config["ram"]["length"] = 1 << 20;
    }

    incomplete_machine_fixture(const incomplete_machine_fixture &other) = delete;
    incomplete_machine_fixture(incomplete_machine_fixture &&other) noexcept = delete;
    incomplete_machine_fixture &operator=(const incomplete_machine_fixture &other) = delete;
    incomplete_machine_fixture &operator=(incomplete_machine_fixture &&other) noexcept = delete;

protected:
    nlohmann::json _machine_config{};
};

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_machine_test, incomplete_machine_fixture) {
    const auto dumped_config = _machine_config.dump();
    cm_error error_code = cm_create_new(dumped_config.c_str(), nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("invalid new machine output");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_pma_overlapping_test, incomplete_machine_fixture) {
    _machine_config["flash_drive"] = nlohmann::json{{{"start", 0x80000000000000}, {"length", 0x3c00000}},
        {{"start", 0x7ffffffffff000}, {"length", 0x2000}}};
    const auto dumped_config = _machine_config.dump();

    cm_error error_code = cm_create_new(dumped_config.c_str(), nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("address range of flash drive 1 overlaps with address range of existing flash drive 0");
    BOOST_CHECK_EQUAL(origin, result);
}

class machine_flash_simple_fixture : public incomplete_machine_fixture {
public:
    machine_flash_simple_fixture() {
        _machine_config["flash_drive"] = {{{"start", 0x80000000000000}, {"length", 0x3c00000}, {"read_only", false},
            {"backing_store", {{"shared", false}, {"truncate", false}, {"data_filename", ""}, {"dht_filename", ""}}}}};
    }

    machine_flash_simple_fixture(const machine_flash_simple_fixture &other) = delete;
    machine_flash_simple_fixture(machine_flash_simple_fixture &&other) noexcept = delete;
    machine_flash_simple_fixture &operator=(const machine_flash_simple_fixture &other) = delete;
    machine_flash_simple_fixture &operator=(machine_flash_simple_fixture &&other) noexcept = delete;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_alignment_test, machine_flash_simple_fixture) {
    _machine_config["flash_drive"][0]["start"] = 0x80000000000000 - 1;
    const auto dumped_config = _machine_config.dump();

    cm_error error_code = cm_create_new(dumped_config.c_str(), nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("start of flash drive 0 (0x7fffffffffffff) must be aligned to page boundary (every 4096 bytes)");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_not_addressable_test, machine_flash_simple_fixture) {
    _machine_config["flash_drive"][0]["start"] = 0x100000000000000 - 0x3c00000 + 4096;
    _machine_config["flash_drive"][0]["length"] = 0x3c00000;
    const auto dumped_config = _machine_config.dump();

    cm_error error_code = cm_create_new(dumped_config.c_str(), nullptr, &_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("address range of flash drive 0 must use at most 56 bits to be addressable");
    BOOST_CHECK_EQUAL(origin, result);
}

class ordinary_machine_fixture : public incomplete_machine_fixture {
public:
    ordinary_machine_fixture() {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        const auto dumped_config = _machine_config.dump();
        cm_create_new(dumped_config.c_str(), nullptr, &_machine);
    }
    ~ordinary_machine_fixture() {
        std::filesystem::remove_all(_machine_dir_path);
        cm_delete(_machine);
    }

    ordinary_machine_fixture(const ordinary_machine_fixture &other) = delete;
    ordinary_machine_fixture(ordinary_machine_fixture &&other) noexcept = delete;
    ordinary_machine_fixture &operator=(const ordinary_machine_fixture &other) = delete;
    ordinary_machine_fixture &operator=(ordinary_machine_fixture &&other) noexcept = delete;

protected:
    std::string _machine_dir_path;
};

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class serialized_machine_fixture : public ordinary_machine_fixture {
public:
    serialized_machine_fixture() : _machine_config_path{std::filesystem::temp_directory_path() / "machine"} {
        cm_error error_code = cm_store(_machine, _machine_config_path.string().c_str());
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
        BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    }

    ~serialized_machine_fixture() {
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

    cm_machine *restored_machine{};
    cm_error error_code = cm_load_new(_machine_config_path.c_str(), nullptr, &restored_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(std::string(cm_get_last_error_message()), expected_err.str());

    cm_delete(restored_machine);
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
    cm_error error_code = cm_store(_machine, _broken_machine_path.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK(std::filesystem::exists(_broken_machine_path));
}

// check that test config version is consistent with the generated config version
BOOST_FIXTURE_TEST_CASE_NOLINT(store_machine_config_version_test, store_file_fixture) {
    // store machine
    BOOST_REQUIRE(!std::filesystem::exists(_broken_machine_path));
    cm_error error_code = cm_store(_machine, _broken_machine_path.c_str());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
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
    cm_error error_code = cm_store(nullptr, _machine_dir_path.c_str());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    BOOST_CHECK_EQUAL(std::string("invalid machine"), std::string(cm_get_last_error_message()));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_empty_dir_path_test, ordinary_machine_fixture) {
    cm_error error_code = cm_store(_machine, "");
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_SYSTEM_ERROR);
    std::string result = cm_get_last_error_message();
    BOOST_REQUIRE(result.find("error creating directory") == 0);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_machine_test, ordinary_machine_fixture) {
    cm_error error_code = cm_store(_machine, _machine_dir_path.c_str());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_load_new(_machine_dir_path.c_str(), nullptr, nullptr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(serde_complex_test, ordinary_machine_fixture) {
    cm_error error_code = cm_store(_machine, _machine_dir_path.c_str());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_machine *restored_machine{};
    error_code = cm_load_new(_machine_dir_path.c_str(), nullptr, &restored_machine);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_hash origin_hash{};
    error_code = cm_get_root_hash(_machine, &origin_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    cm_hash restored_hash{};
    error_code = cm_get_root_hash(restored_machine, &restored_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL(0, memcmp(origin_hash, restored_hash, sizeof(cm_hash)));

    cm_delete(restored_machine);
}

BOOST_AUTO_TEST_CASE_NOLINT(get_root_hash_null_machine_test) {
    cm_hash restored_hash;
    cm_error error_code = cm_get_root_hash(nullptr, &restored_hash);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_null_test) {
    cm_delete(nullptr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_null_hash_test, ordinary_machine_fixture) {
    cm_error error_code = cm_get_root_hash(_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_machine_hash_test, ordinary_machine_fixture) {
    cm_hash result_hash;
    cm_error error_code = cm_get_root_hash(_machine, &result_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), result_hash, result_hash + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_proof_null_machine_test) {
    const char *proof{};
    cm_error error_code = cm_get_proof(nullptr, 0, 12, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_invalid_address_test, ordinary_machine_fixture) {
    const char *proof{};
    cm_error error_code = cm_get_proof(_machine, 1, 12, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_DOMAIN_ERROR);

    std::string result = cm_get_last_error_message();
    std::string origin("address not aligned to log2_size");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_invalid_log2_test, ordinary_machine_fixture) {
    const char *proof{};

    // log2_root_size = 64
    cm_error error_code = cm_get_proof(_machine, 0, 65, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = cm_get_last_error_message();
    std::string origin("invalid log2_size");
    BOOST_CHECK_EQUAL(origin, result);

    // log2_word_size = 3
    error_code = cm_get_proof(_machine, 0, 2, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    result = cm_get_last_error_message();
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_inconsistent_tree_test, ordinary_machine_fixture) {
    const char *proof{};
    cm_error error_code = cm_get_proof(_machine, 0, 64, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    // merkle tree is always consistent now as it updates on access

    error_code = cm_get_proof(_machine, 0, CM_TREE_LOG2_PAGE_SIZE, &proof);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_null_proof_test, ordinary_machine_fixture) {
    cm_error error_code = cm_get_proof(_machine, 0, 12, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_machine_hash_test, ordinary_machine_fixture) {
    const char *proof_str{};
    cm_error error_code = cm_get_proof(_machine, 0, 12, &proof_str);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    const auto proof = cartesi::from_json<cartesi::not_default_constructible<cartesi::machine_merkle_tree::proof_type>>(
        proof_str, "proof")
                           .value();
    auto proof_root_hash = proof.get_root_hash();
    auto verification = calculate_proof_root_hash(proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());

    BOOST_REQUIRE(proof.get_log2_root_size() == 64);
    BOOST_REQUIRE(proof.get_sibling_hashes().size() == 52);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_word_null_machine_test) {
    uint64_t word_value = 0;
    cm_error error_code = cm_read_word(nullptr, 0x100, &word_value);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_invalid_address_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    cm_error error_code = cm_read_word(_machine, 0xffffffff, &word_value);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_DOMAIN_ERROR);

    std::string result = cm_get_last_error_message();
    std::string origin("attempted misaligned read from word");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_null_output_test, default_machine_fixture) {
    cm_error error_code = cm_read_word(_machine, 0x100, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_basic_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    uint64_t pc_addr{};
    BOOST_CHECK_EQUAL(cm_get_reg_address(_machine, CM_REG_PC, &pc_addr), CM_ERROR_OK);
    cm_error error_code = cm_read_word(_machine, pc_addr, &word_value);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(word_value, static_cast<uint64_t>(0x80000000));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_memory_null_machine_test) {
    std::array<uint8_t, sizeof(uint64_t)> rd{};
    cm_error error_code = cm_read_memory(nullptr, 0x100, rd.data(), rd.size());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_memory_zero_data_size_test, ordinary_machine_fixture) {
    std::array<uint8_t, sizeof(uint64_t)> rd_origin{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    std::array<uint8_t, sizeof(uint64_t)> rd{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    cm_error error_code = cm_read_memory(_machine, 0x100, rd.data(), 0);

    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL_COLLECTIONS(rd.begin(), rd.end(), rd_origin.begin(), rd_origin.end());
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_null_data_test, ordinary_machine_fixture) {
    cm_error error_code = cm_read_memory(_machine, 0x80000000, nullptr, 1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    error_code = cm_write_memory(_machine, 0x80000000, nullptr, 1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_memory_null_machine_test) {
    std::array<uint8_t, sizeof(uint64_t)> wd{};
    cm_error error_code = cm_write_memory(nullptr, 0x100, wd.data(), wd.size());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_zero_data_test, ordinary_machine_fixture) {
    cm_error error_code = cm_write_memory(_machine, 0x80000000, nullptr, 0);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_null_data_size_mismatch_test, ordinary_machine_fixture) {
    cm_error error_code = cm_write_memory(_machine, 0x80000000, nullptr, 1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_null_data_test, ordinary_machine_fixture) {
    cm_error error_code = cm_read_virtual_memory(_machine, 0x80000000, nullptr, 1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    error_code = cm_write_virtual_memory(_machine, 0x80000000, nullptr, 1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_invalid_address_range_test, ordinary_machine_fixture) {
    uint64_t write_value = 0x1234;
    uint64_t address = 0x100;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = cm_get_last_error_message();
    std::string origin("address range to write is not entirely in single memory range");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_word_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_read_word(_machine, address, &read_value);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_memory_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    std::array<uint8_t, sizeof(uint64_t)> read_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
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
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
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
    memset(write_data.data(), 0xda, data_size);

    cm_error error_code = cm_write_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL_COLLECTIONS(write_data.begin(), write_data.end(), read_data.begin(), read_data.end());
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_virtual_memory_invalid_address_range_test, ordinary_machine_fixture) {
    uint64_t write_value = 0x1234;
    uint64_t address = 0x100;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = cm_get_last_error_message();
    std::string origin("address range to write is not entirely in single memory range");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_virtual_memory_basic_test, ordinary_machine_fixture) {
    uint64_t read_value = 0;
    uint64_t write_value = 0x1234;
    uint64_t address = 0x80000000;
    std::array<uint8_t, sizeof(uint64_t)> write_data{};
    std::array<uint8_t, sizeof(uint64_t)> read_data{};
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    memcpy(&read_value, read_data.data(), read_data.size());
    BOOST_CHECK_EQUAL(read_value, write_value);

    uint64_t paddr = 0;
    error_code = cm_translate_virtual_address(_machine, address, &paddr);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
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
    memcpy(write_data.data(), &write_value, write_data.size());

    cm_error error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
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
    memset(write_data.data(), 0xda, data_size);

    cm_error error_code = cm_write_virtual_memory(_machine, address, write_data.data(), write_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_read_virtual_memory(_machine, address, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL_COLLECTIONS(write_data.begin(), write_data.end(), read_data.begin(), read_data.end());
}

// NOLINTNEXTLINE
#define CHECK_READER_FAILS_ON_nullptr_MACHINE(T, reader_f)                                                             \
    BOOST_FIXTURE_TEST_CASE_NOLINT(read_##reader_f##_null_machine_test, ordinary_machine_fixture) {                    \
        T out{};                                                                                                       \
        cm_error error_code = cm_read_##reader_f(nullptr, &out);                                                       \
        BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);                                                    \
        error_code = cm_read_##reader_f(_machine, nullptr);                                                            \
        BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);                                                    \
    }

BOOST_FIXTURE_TEST_CASE_NOLINT(ids_read_test, ordinary_machine_fixture) {
    uint64_t vendorid{};
    uint64_t archid{};
    uint64_t impid{};

    cm_error error_code = cm_read_reg(_machine, CM_REG_MVENDORID, &vendorid);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(vendorid, static_cast<uint64_t>(cartesi::MVENDORID_INIT));

    error_code = cm_read_reg(_machine, CM_REG_MARCHID, &archid);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(archid, static_cast<uint64_t>(cartesi::MARCHID_INIT));

    error_code = cm_read_reg(_machine, CM_REG_MIMPID, &impid);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(impid, static_cast<uint64_t>(cartesi::MIMPID_INIT));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_tohost_read_complex_test, ordinary_machine_fixture) {
    cm_error error_code = cm_write_reg(_machine, CM_REG_HTIF_TOHOST, 0x1111111111111111);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    uint64_t htif_dev{};
    uint64_t htif_cmd{};
    uint64_t htif_data{};
    error_code = cm_read_reg(_machine, CM_REG_HTIF_TOHOST_DEV, &htif_dev);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(htif_dev, static_cast<uint64_t>(0x11));

    error_code = cm_read_reg(_machine, CM_REG_HTIF_TOHOST_CMD, &htif_cmd);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(htif_cmd, static_cast<uint64_t>(0x11));

    error_code = cm_read_reg(_machine, CM_REG_HTIF_TOHOST_REASON, &htif_data);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x1111));

    error_code = cm_read_reg(_machine, CM_REG_HTIF_TOHOST_DATA, &htif_data);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x11111111));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_fromhost_read_complex_test, ordinary_machine_fixture) {
    uint64_t write_data = 0x0;
    cm_error error_code = cm_write_reg(_machine, CM_REG_HTIF_FROMHOST, write_data);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    write_data = 0x11111111;
    error_code = cm_write_reg(_machine, CM_REG_HTIF_FROMHOST_DATA, write_data);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    uint64_t htif_data{};
    error_code = cm_read_reg(_machine, CM_REG_HTIF_FROMHOST_DATA, &htif_data);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x11111111));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_initial_config_null_machine_test) {
    const char *cfg{};
    cm_error error_code = cm_get_initial_config(nullptr, &cfg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_null_output_test, ordinary_machine_fixture) {
    cm_error error_code = cm_get_initial_config(_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_basic_test, ordinary_machine_fixture) {
    const char *cfg{};
    cm_error error_code = cm_get_initial_config(_machine, &cfg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    // flash_drive comparison is not performed here
    // 'cause it's not a part of the initial config
    BOOST_CHECK_EQUAL(std::string(cfg), _machine_config.dump());
}

BOOST_AUTO_TEST_CASE_NOLINT(verify_dirty_page_maps_null_machine_test) {
    bool result{};
    cm_error error_code = cm_verify_dirty_page_maps(nullptr, &result);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_null_output_test, ordinary_machine_fixture) {
    cm_error error_code = cm_verify_dirty_page_maps(_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_success_test, ordinary_machine_fixture) {
    bool result{};
    cm_error error_code = cm_verify_dirty_page_maps(_machine, &result);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK(result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_flash_config_test, ordinary_machine_fixture) {
    const auto dumped_range =
        nlohmann::json{{"start", 0}, {"length", 0}, {"backing_store", {{"shared", false}}}}.dump();
    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("attempt to replace inexistent memory range");
    BOOST_CHECK_EQUAL(origin, result);
}

class flash_drive_machine_fixture : public machine_flash_simple_fixture {
public:
    flash_drive_machine_fixture() :
        _flash_size{0x3c00000},
        _flash_file{"/tmp/data.bin"},
        _flash_data{"test data 1234567890"} {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        const auto dumped_config = _machine_config.dump();
        cm_error error_code = cm_create_new(dumped_config.c_str(), nullptr, &_machine);
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
        BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

        std::ofstream flash_stream(_flash_file);
        flash_stream << _flash_data;
        flash_stream.close();
        std::filesystem::resize_file(_flash_file, _flash_size);
    }

    ~flash_drive_machine_fixture() {
        cm_delete(_machine);
        std::filesystem::remove_all(_machine_dir_path);
        std::filesystem::remove(_flash_file);
    }

    flash_drive_machine_fixture(const flash_drive_machine_fixture &other) = delete;
    flash_drive_machine_fixture(flash_drive_machine_fixture &&other) noexcept = delete;
    flash_drive_machine_fixture &operator=(const flash_drive_machine_fixture &other) = delete;
    flash_drive_machine_fixture &operator=(flash_drive_machine_fixture &&other) noexcept = delete;

protected:
    size_t _flash_size;
    std::string _flash_file;
    std::string _flash_data;
    std::string _machine_dir_path;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_flash_drive_test, flash_drive_machine_fixture) {
    const char *cfg{};
    cm_error error_code = cm_get_initial_config(_machine, &cfg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(std::string(cfg), _machine_config.dump());
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_null_memory_range_test, flash_drive_machine_fixture) {
    cm_error error_code = cm_replace_memory_range(_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin = "invalid memory range configuration";
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_machine_test, flash_drive_machine_fixture) {
    const auto dumped_range =
        nlohmann::json{{{"start", 0}, {"length", 0}, {{"backing_store", {"shared", false}}}}}.dump();
    cm_error error_code = cm_replace_memory_range(nullptr, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_empty_memory_range_test, flash_drive_machine_fixture) {
    const auto dumped_range =
        nlohmann::json{{{"start", 0}, {"length", 0}, {{"backing_store", {"shared", false}}}}}.dump();
    cm_error error_code = cm_replace_memory_range(nullptr, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_pma_test, flash_drive_machine_fixture) {
    const auto dumped_range = nlohmann::json{{"start", 0x9000000000000}, {"length", _flash_size},
        {"backing_store", {{"shared", true}, {"data_filename", _flash_file}}}}
                                  .dump();
    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_length_test, flash_drive_machine_fixture) {
    _flash_size = 0x3c00;
    std::filesystem::resize_file(_flash_file, _flash_size);
    const auto dumped_range = nlohmann::json{{"start", 0x80000000000000}, {"length", _flash_size},
        {"backing_store", {{"shared", true}, {"data_filename", _flash_file}}}}
                                  .dump();

    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_file_length_mismatch_test, flash_drive_machine_fixture) {
    _flash_size = 0x3c00;
    const auto dumped_range = nlohmann::json{{"start", 0x80000000000000}, {"length", _flash_size},
        {"backing_store", {{"shared", true}, {"data_filename", _flash_file}}}}
                                  .dump();
    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_zero_length_test, flash_drive_machine_fixture) {
    _flash_size = 0x0;
    const auto dumped_range = nlohmann::json{{"start", 0x80000000000000}, {"length", _flash_size},
        {"backing_store", {{"shared", true}, {"data_filename", _flash_file}}}}
                                  .dump();

    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin = "attempt to replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_basic_test, flash_drive_machine_fixture) {
    const auto dumped_range = nlohmann::json{{"start", 0x80000000000000}, {"length", _flash_size},
        {"backing_store", {{"shared", true}, {"data_filename", _flash_file}}}}
                                  .dump();
    cm_error error_code = cm_replace_memory_range(_machine, dumped_range.c_str());
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    std::array<uint8_t, 20> read_data{};
    error_code = cm_read_memory(_machine, 0x80000000000000, read_data.data(), read_data.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string read_string{reinterpret_cast<char *>(read_data.data()), read_data.size()};
    BOOST_CHECK_EQUAL(_flash_data, read_string);
}

BOOST_AUTO_TEST_CASE_NOLINT(delete_null_machine_test) {
    cm_delete(nullptr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(delete_basic_test, ordinary_machine_fixture) {
    cm_delete(_machine);
    _machine = nullptr;
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_x_basic_test, ordinary_machine_fixture) {
    uint64_t x_origin = 42;
    uint64_t x_read{};
    cm_error error_code = cm_write_reg(_machine, CM_REG_X2, x_origin);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_read_reg(_machine, CM_REG_X2, &x_read);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(x_origin, x_read);

    uint64_t x2_addr{};
    BOOST_CHECK_EQUAL(cm_get_reg_address(_machine, CM_REG_X2, &x2_addr), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x10), x2_addr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_f_basic_test, ordinary_machine_fixture) {
    uint64_t f_origin = 42;
    uint64_t f_read{};
    cm_error error_code = cm_write_reg(_machine, CM_REG_F2, f_origin);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_read_reg(_machine, CM_REG_F2, &f_read);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(f_origin, f_read);

    uint64_t f2_addr{};
    BOOST_CHECK_EQUAL(cm_get_reg_address(_machine, CM_REG_F2, &f2_addr), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x128), f2_addr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_uarch_x_basic_test, ordinary_machine_fixture) {
    uint64_t uarch_x_origin = 42;
    uint64_t uarch_x_read{};
    cm_error error_code = cm_write_reg(_machine, CM_REG_UARCH_X2, uarch_x_origin);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_read_reg(_machine, CM_REG_UARCH_X2, &uarch_x_read);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(uarch_x_origin, uarch_x_read);

    uint64_t uarch_x2_addr{};
    BOOST_CHECK_EQUAL(cm_get_reg_address(_machine, CM_REG_UARCH_X2, &uarch_x2_addr), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(cartesi::AR_SHADOW_UARCH_STATE_START + 40), uarch_x2_addr);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_reg_null_machine_test) {
    uint64_t val{};
    cm_error error_code = cm_read_reg(nullptr, CM_REG_MCYCLE, &val);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_reg_null_output_test, ordinary_machine_fixture) {
    cm_error error_code = cm_read_reg(_machine, CM_REG_MCYCLE, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_reg_null_machine_test) {
    cm_error error_code = cm_write_reg(nullptr, CM_REG_MCYCLE, 3);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_reg_basic_test, ordinary_machine_fixture) {
    uint64_t reg_origin = 42;
    uint64_t reg_read{};

    cm_error error_code = cm_write_reg(_machine, CM_REG_MCYCLE, reg_origin);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_read_reg(_machine, CM_REG_MCYCLE, &reg_read);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK_EQUAL(reg_origin, reg_read);

    uint64_t pc_addr{};
    BOOST_CHECK_EQUAL(cm_get_reg_address(_machine, CM_REG_PC, &pc_addr), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x108), pc_addr);
}

BOOST_AUTO_TEST_CASE_NOLINT(verify_merkle_tree_null_machine_test) {
    bool ret{};
    cm_error error_code = cm_verify_merkle_tree(nullptr, &ret);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_null_output_test, ordinary_machine_fixture) {
    cm_error error_code = cm_verify_merkle_tree(_machine, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_basic_test, ordinary_machine_fixture) {
    bool ret{};
    cm_error error_code = cm_verify_merkle_tree(_machine, &ret);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    BOOST_CHECK(ret);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_log_null_log_test, default_machine_fixture) {
    cm_error error_code = cm_verify_step_uarch(nullptr, nullptr, nullptr, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("invalid access log");
    BOOST_CHECK_EQUAL(origin, result);
}

class access_log_machine_fixture : public incomplete_machine_fixture {
public:
    access_log_machine_fixture() {
        _log_type = CM_ACCESS_LOG_TYPE_ANNOTATIONS;
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();

        uint32_t test_uarch_ram[] = {
            0x07b00513,                                                            //  li	a0,123
            (cartesi::uarch_ecall_functions::UARCH_ECALL_FN_HALT << 20) | 0x00893, // li a7,halt
            0x00000073,                                                            // ecall
        };
        std::ofstream of(_uarch_ram_path, std::ios::binary);
        of.write(static_cast<char *>(static_cast<void *>(&test_uarch_ram)), sizeof(test_uarch_ram));
        of.close();
        _machine_config["uarch"]["ram"] = {{"backing_store", {{"data_filename", _uarch_ram_path}}}};
        const auto dumped_config = _machine_config.dump();

        cm_create_new(dumped_config.c_str(), nullptr, &_machine);
    }
    ~access_log_machine_fixture() {
        cm_delete(_machine);
        std::filesystem::remove_all(_machine_dir_path);
        std::filesystem::remove_all(_uarch_ram_path);
    }

    access_log_machine_fixture(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture(access_log_machine_fixture &&other) noexcept = delete;
    access_log_machine_fixture &operator=(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture &operator=(access_log_machine_fixture &&other) noexcept = delete;

protected:
    std::string _machine_dir_path;
    const std::string _uarch_ram_path = "/tmp/test-uarch-ram.bin";
    const char *_access_log{};
    int _log_type{};
};

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_machine_test, access_log_machine_fixture) {
    cm_error error_code = cm_log_step_uarch(nullptr, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_access_log_test, access_log_machine_fixture) {
    cm_error error_code = cm_log_step_uarch(_machine, _log_type, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_null_hash0_test, access_log_machine_fixture) {
    cm_error error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_hash hash1;
    error_code = cm_verify_step_uarch(nullptr, nullptr, _access_log, &hash1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("invalid hash");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_null_hash1_test, access_log_machine_fixture) {
    cm_error error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_hash hash0;
    error_code = cm_verify_step_uarch(nullptr, &hash0, _access_log, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("invalid hash");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_step_uarch_null_access_log_test, access_log_machine_fixture) {
    cm_hash hash0;
    cm_hash hash1;
    cm_error error_code = cm_verify_step_uarch(nullptr, &hash0, nullptr, &hash1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("invalid access log");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(log_step_uarch_until_halt, access_log_machine_fixture) {
    cm_hash hash0{};
    cm_hash hash1{};
    cm_hash hash2{};
    cm_hash hash3{};
    cm_hash hash4{};

    cm_error error_code{};
    uint64_t cycle{};
    uint64_t halt{1};

    // at micro cycle 0
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // not halted
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(halt, 0);

    // get initial hash
    error_code = cm_get_root_hash(_machine, &hash0);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // step 1
    error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash1);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch(nullptr, &hash0, _access_log, &hash1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    // step 2
    error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash2);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch(nullptr, &hash1, _access_log, &hash2);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    // step 3
    error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash3);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch(nullptr, &hash2, _access_log, &hash3);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // step 4
    error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    // get hash after step
    error_code = cm_get_root_hash(_machine, &hash4);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    // verify
    error_code = cm_verify_step_uarch(_machine, &hash3, _access_log, &hash4);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);

    // at micro cycle 4
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 3);

    // halted
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(halt, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_complex_test, access_log_machine_fixture) {
    cm_hash hash0;
    cm_hash hash1;

    cm_error error_code = cm_get_root_hash(_machine, &hash0);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_get_root_hash(_machine, &hash1);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    error_code = cm_verify_step_uarch(_machine, &hash0, _access_log, &hash1);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_hash_test, access_log_machine_fixture) {

    cm_error error_code = cm_log_step_uarch(_machine, _log_type, &_access_log);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_hash hash1;
    error_code = cm_get_root_hash(_machine, &hash1);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash1, hash1 + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(machine_run_null_machine_test) {
    cm_break_reason break_reason{};
    cm_error error_code = cm_run(nullptr, 1000, &break_reason);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    BOOST_CHECK_EQUAL(break_reason, CM_BREAK_REASON_FAILED);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_1000_cycle_test, ordinary_machine_fixture) {
    cm_error error_code = cm_run(_machine, 1000, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    uint64_t read_mcycle{};
    error_code = cm_read_reg(_machine, CM_REG_MCYCLE, &read_mcycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL(read_mcycle, static_cast<uint64_t>(1000));

    cm_hash hash_1000;
    error_code = cm_get_root_hash(_machine, &hash_1000);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_1000, hash_1000 + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_to_past_test, ordinary_machine_fixture) {
    uint64_t cycle_num = 1000;
    uint64_t cycle_num_to_past = 100;

    cm_error error_code = cm_run(_machine, cycle_num, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    uint64_t read_mcycle{};
    error_code = cm_read_reg(_machine, CM_REG_MCYCLE, &read_mcycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL(read_mcycle, cycle_num);

    error_code = cm_run(_machine, cycle_num_to_past, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = cm_get_last_error_message();
    std::string origin("mcycle is past");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_long_cycle_test, ordinary_machine_fixture) {
    cm_error error_code = cm_run(_machine, 600000, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    uint64_t read_mcycle{};
    error_code = cm_read_reg(_machine, CM_REG_MCYCLE, &read_mcycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_CHECK_EQUAL(read_mcycle, static_cast<uint64_t>(600000));

    cm_hash hash_end;
    error_code = cm_get_root_hash(_machine, &hash_end);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_end, hash_end + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(machine_run_uarch_null_machine_test) {
    auto status{CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE};
    cm_error error_code = cm_run_uarch(nullptr, 1000, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_uarch_advance_one_cycle, access_log_machine_fixture) {

    // ensure that uarch cycle is 0
    uint64_t cycle{};
    cm_error error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // advance one uarch cycle
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, 1, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE);

    // confirm uarch cycle was incremented
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(cycle, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_uarch_advance_until_halt, access_log_machine_fixture) {
    // ensure that uarch cycle is 0
    uint64_t cycle{};
    cm_error error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // ensure not halted
    uint64_t halt{1};
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(halt, 0);

    // save initial hash
    cm_hash initial_hash{};
    cm_get_root_hash(_machine, &initial_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // advance one micro cycle
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, 1, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE);

    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, 1);

    // hash after one step should be different from the initial hash
    cm_hash one_cycle_hash{};
    cm_get_root_hash(_machine, &one_cycle_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK(0 != memcmp(initial_hash, one_cycle_hash, sizeof(cm_hash)));

    // advance more micro cycles past the point where the program halts (see hard-coded micro code in test fixture )
    error_code = cm_run_uarch(_machine, 100, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    // assert result status reports
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // confirm uarch cycle advanced
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(cycle, 3);

    // assert halt flag is set
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(halt, 1);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_reset_uarch, ordinary_machine_fixture) {
    // ensure that uarch cycle is 0
    uint64_t halt_cycle{};
    uint64_t cycle{};
    cm_error error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(cycle, 0);

    // ensure not halted
    uint64_t halt{1};
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(halt, 0);

    // save initial uarch ram
    std::vector<unsigned char> initial_uarch_ram(cartesi::UARCH_RAM_LENGTH);
    error_code =
        cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, initial_uarch_ram.data(), initial_uarch_ram.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    // run until halt
    auto status{CM_UARCH_BREAK_REASON_UARCH_HALTED};
    error_code = cm_run_uarch(_machine, -1, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // confirm if halt flag is set
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(halt, 1);

    // save halt cycle
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &halt_cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE(halt_cycle > 0);

    // try run_uarch past the halted cycle
    error_code = cm_run_uarch(_machine, halt_cycle + 1, &status);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(status, CM_UARCH_BREAK_REASON_UARCH_HALTED);

    // should stay at halt cycle
    error_code = cm_read_reg(_machine, CM_REG_UARCH_CYCLE, &cycle);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cycle, halt_cycle);

    // change the uarch ram in order to confirm if reset will restore it to the initial value
    std::array<uint8_t, 8> random_bytes{1, 2, 3, 4, 5, 6, 7, 8};
    error_code = cm_write_memory(_machine, cartesi::AR_UARCH_RAM_START, random_bytes.data(), random_bytes.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // grab the modified ram bytes
    std::vector<unsigned char> modified_uarch_ram(cartesi::AR_UARCH_RAM_LENGTH);
    error_code = cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, modified_uarch_ram.data(),
        modified_uarch_ram.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    // ensure that modified ram is different from the one initially saved
    BOOST_REQUIRE(initial_uarch_ram != modified_uarch_ram);

    // reset state
    error_code = cm_reset_uarch(_machine);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    // halt flag should be cleared
    error_code = cm_read_reg(_machine, CM_REG_UARCH_HALT_FLAG, &halt);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    BOOST_REQUIRE_EQUAL(halt, 0);

    // grab the ram after reset
    std::vector<unsigned char> reset_uarch_ram(cartesi::UARCH_RAM_LENGTH);
    error_code =
        cm_read_memory(_machine, cartesi::UARCH_RAM_START_ADDRESS, reset_uarch_ram.data(), reset_uarch_ram.size());
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));

    // confirm ram was restored to initial state
    BOOST_REQUIRE(initial_uarch_ram == reset_uarch_ram);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_verify_merkle_tree_root_updates_test, ordinary_machine_fixture) {

    cm_hash start_hash;
    cm_error error_code = cm_get_root_hash(_machine, &start_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    auto verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_hash, start_hash + sizeof(cm_hash));

    error_code = cm_run(_machine, 1000, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    cm_hash end_hash;
    error_code = cm_get_root_hash(_machine, &end_hash);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(std::string(cm_get_last_error_message()), std::string(""));
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_hash, end_hash + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_verify_merkle_tree_proof_updates_test, ordinary_machine_fixture) {
    const char *proof_str{};
    cm_error error_code = cm_get_proof(_machine, 0, 12, &proof_str);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    auto proof = cartesi::from_json<cartesi::not_default_constructible<cartesi::machine_merkle_tree::proof_type>>(
        proof_str, "proof")
                     .value();
    auto proof_root_hash = proof.get_root_hash();
    auto verification = calculate_proof_root_hash(proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());

    error_code = cm_run(_machine, 1000, nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));

    error_code = cm_get_proof(_machine, 0, 12, &proof_str);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(""), std::string(cm_get_last_error_message()));
    proof = cartesi::from_json<cartesi::not_default_constructible<cartesi::machine_merkle_tree::proof_type>>(proof_str,
        "proof")
                .value();
    proof_root_hash = proof.get_root_hash();
    verification = calculate_proof_root_hash(proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());
    verification = calculate_emulator_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), proof_root_hash.begin(),
        proof_root_hash.end());
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
