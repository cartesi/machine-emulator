#define BOOST_TEST_MODULE Machine C API test // NOLINT(cppcoreguidelines-macro-usage)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/process.hpp>
#include <boost/process/search_path.hpp>
#include <boost/test/execution_monitor.hpp>
#include <boost/test/included/unit_test.hpp>
#pragma GCC diagnostic pop

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <thread>
#include <tuple>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include "cartesi-machine.pb.h"
#pragma GCC diagnostic pop

#include "grpc-machine-c-api.h"
#include "machine-c-api.h"
#include "test-utils.h"

// NOLINTNEXTLINE
#define BOOST_AUTO_TEST_CASE_NOLINT(...) BOOST_AUTO_TEST_CASE(__VA_ARGS__)
// NOLINTNEXTLINE
#define BOOST_FIXTURE_TEST_CASE_NOLINT(...) BOOST_FIXTURE_TEST_CASE(__VA_ARGS__)

static void monitor_system_throw(std::function<void()> const &f) {
    boost::execution_monitor ex_mon;
    ex_mon.p_catch_system_errors.value = true;
    BOOST_CHECK_THROW(ex_mon.vexecute(f), boost::execution_exception);
}

static hash_type get_verification_root_hash(cm_machine *machine) {
    std::array dump_list{"0000000000000000--0000000000001000.bin", "0000000000001000--000000000000f000.bin",
        "0000000000010000--0000000000001000.bin", "0000000002000000--00000000000c0000.bin",
        "0000000040008000--0000000000001000.bin", "0000000080000000--0000000000100000.bin"};

    char *err_msg{};
    int error_code = cm_dump_pmas(machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    auto hash = calculate_emulator_hash(dump_list);

    for (const auto &file : dump_list) {
        std::filesystem::remove(file);
    }

    return hash;
}

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

BOOST_AUTO_TEST_CASE_NOLINT(get_default_machine_config_basic_test) {
    const cm_machine_config *config{};
    char *err_msg{};
    int error_code = cm_get_default_config(&config, &err_msg);
    BOOST_TEST_CHECK(config != nullptr);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
}

class default_machine_fixture {
public:
    default_machine_fixture() : _machine(nullptr), _default_machine_config(cm_new_default_machine_config()) {}

    ~default_machine_fixture() {
        cm_delete_machine_config(_default_machine_config);
    }

    default_machine_fixture(const default_machine_fixture &other) = delete;
    default_machine_fixture(default_machine_fixture &&other) noexcept = delete;
    default_machine_fixture &operator=(const default_machine_fixture &other) = delete;
    default_machine_fixture &operator=(default_machine_fixture &&other) noexcept = delete;

protected:
    cm_machine_runtime_config _runtime_config{};
    cm_machine *_machine;
    const cm_machine_config *_default_machine_config;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_unknown_dir_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_load_machine("/unknown_dir", &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    std::string origin("unable to open '/unknown_dir/config.protobuf' for reading");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_path_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_load_machine(nullptr, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    std::string origin("unable to open '/config.protobuf' for reading");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_config_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create_machine(nullptr, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_rt_config_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create_machine(_default_machine_config, nullptr, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_error_placeholder_test, default_machine_fixture) {
    auto f = [rtc = &_runtime_config, cfg = _default_machine_config, m = &_machine]() {
        cm_create_machine(cfg, rtc, m, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_default_machine_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_create_machine(_default_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("ROM image filename is undefined");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

static char *new_cstr(const char *str) {
    auto size = strlen(str) + 1;
    auto *copy = new char[size];
    strncpy(copy, str, size);
    return copy;
}

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

        target->rom.bootargs = new_cstr(source->rom.bootargs);
        target->rom.image_filename = new_cstr(source->rom.image_filename);

        target->flash_drive.count = source->flash_drive.count;
        target->flash_drive.entry = new cm_memory_range_config[source->flash_drive.count]{};
        for (size_t i = 0; i < target->flash_drive.count; ++i) {
            target->flash_drive.entry[i] = source->flash_drive.entry[i];
            target->flash_drive.entry[i].image_filename = new_cstr(source->flash_drive.entry[i].image_filename);
        }

        target->clint = source->clint;
        target->htif = source->htif;
        target->rollup = source->rollup;
    }

    static void _cleanup_machine_config(cm_machine_config *config) {
        for (size_t i = 0; i < config->flash_drive.count; ++i) {
            delete[] config->flash_drive.entry[i].image_filename;
        }
        delete[] config->flash_drive.entry;
        delete[] config->rom.image_filename;
        delete[] config->rom.bootargs;
        delete[] config->ram.image_filename;
    }

    void _set_rom_image(const std::string &image_name) {
        delete[] _machine_config.rom.image_filename;
        _machine_config.rom.image_filename = new_cstr(image_name.c_str());
    }

    void _setup_flash(std::list<cm_memory_range_config> &&configs) {
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
};

class machine_rom_fixture : public incomplete_machine_fixture {
public:
    machine_rom_fixture() {
        std::ofstream output(_rom_path);
        output.close();
        _set_rom_image(_rom_path);
    }
    ~machine_rom_fixture() {
        std::filesystem::remove(_rom_path);
    }

    machine_rom_fixture(const machine_rom_fixture &other) = delete;
    machine_rom_fixture(machine_rom_fixture &&other) noexcept = delete;
    machine_rom_fixture &operator=(const machine_rom_fixture &other) = delete;
    machine_rom_fixture &operator=(machine_rom_fixture &&other) noexcept = delete;

protected:
    const std::string _rom_path = "./empty-rom.bin";
};

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_null_machine_test, machine_rom_fixture) {
    auto f = [cfg = &_machine_config, rtc = &_runtime_config]() {
        char *err_msg{};
        cm_create_machine(cfg, rtc, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_machine_unknown_rom_file_test, incomplete_machine_fixture) {
    _set_rom_image("/unknown/file.bin");
    char *err_msg{};
    int error_code = cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    std::string origin("error opening backing file '/unknown/file.bin': No such file or directory");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

class machine_rom_flash_fixture : public machine_rom_fixture {
public:
    machine_rom_flash_fixture() {
        cm_memory_range_config flash1_cfg = {0x80000000000000, 0x3c00000, true, _flash1_path.c_str()};
        cm_memory_range_config flash2_cfg = {0x7ffffffffff000, 0x2000, true, _flash2_path.c_str()};
        _setup_flash({flash1_cfg, flash2_cfg});
    }

    ~machine_rom_flash_fixture() {
        std::filesystem::remove(_flash1_path);
        std::filesystem::remove(_flash2_path);
    }

    machine_rom_flash_fixture(const machine_rom_flash_fixture &other) = delete;
    machine_rom_flash_fixture(machine_rom_flash_fixture &&other) noexcept = delete;
    machine_rom_flash_fixture &operator=(const machine_rom_flash_fixture &other) = delete;
    machine_rom_flash_fixture &operator=(machine_rom_flash_fixture &&other) noexcept = delete;

private:
    const std::string _flash1_path = "./flash1.bin";
    const std::string _flash2_path = "./flash2.bin";
};

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_pma_overlapping_test, machine_rom_flash_fixture) {
    char *err_msg{};
    int error_code = cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("PMA overlaps with existing PMA");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

class machine_rom_flash_simple_fixture : public machine_rom_fixture {
public:
    machine_rom_flash_simple_fixture() {
        _setup_flash(_flash_path);
    }

    ~machine_rom_flash_simple_fixture() {
        std::filesystem::remove(_flash_path);
    }

    machine_rom_flash_simple_fixture(const machine_rom_flash_simple_fixture &other) = delete;
    machine_rom_flash_simple_fixture(machine_rom_flash_simple_fixture &&other) noexcept = delete;
    machine_rom_flash_simple_fixture &operator=(const machine_rom_flash_simple_fixture &other) = delete;
    machine_rom_flash_simple_fixture &operator=(machine_rom_flash_simple_fixture &&other) noexcept = delete;

protected:
    const std::string _flash_path = "./flash.bin";
};

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_alignment_test, machine_rom_flash_simple_fixture) {
    _machine_config.flash_drive.entry[0].start -= 1;

    char *err_msg{};
    int error_code = cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("PMA start must be aligned to page boundary");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_not_addressable_test, machine_rom_flash_simple_fixture) {
    _machine_config.flash_drive.entry[0].start = 0x100000000000000 - 0x3c00000 + 4096;
    _machine_config.flash_drive.entry[0].length = 0x3c00000;

    char *err_msg{};
    int error_code = cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("PMA range must use at most 56 bits to be addressable");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

class ordinary_machine_fixture : public machine_rom_fixture {
public:
    ordinary_machine_fixture() {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        char *err_msg{};
        cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);
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
    return lhs.pc == rhs.pc && lhs.mvendorid == rhs.mvendorid && lhs.marchid == rhs.marchid &&
        lhs.mimpid == rhs.mimpid && lhs.mcycle == rhs.mcycle && lhs.minstret == rhs.minstret &&
        lhs.mstatus == rhs.mstatus && lhs.mtvec == rhs.mtvec && lhs.mscratch == rhs.mscratch && lhs.mepc == rhs.mepc &&
        lhs.mcause == rhs.mcause && lhs.mtval == rhs.mtval && lhs.misa == rhs.misa && lhs.mie == rhs.mie &&
        lhs.mip == rhs.mip && lhs.medeleg == rhs.medeleg && lhs.mideleg == rhs.mideleg &&
        lhs.mcounteren == rhs.mcounteren && lhs.menvcfg == rhs.menvcfg && lhs.stvec == rhs.stvec &&
        lhs.sscratch == rhs.sscratch && lhs.sepc == rhs.sepc && lhs.scause == rhs.scause && lhs.stval == rhs.stval &&
        lhs.satp == rhs.satp && lhs.scounteren == rhs.scounteren && lhs.senvcfg == rhs.senvcfg &&
        lhs.ilrsc == rhs.ilrsc && lhs.iflags == rhs.iflags && lhs.brkflag == rhs.brkflag;
}

bool operator==(const cm_ram_config &lhs, const cm_ram_config &rhs) {
    return (lhs.length == rhs.length && (strcmp(lhs.image_filename, rhs.image_filename) == 0));
}

bool operator==(const cm_rom_config &lhs, const cm_rom_config &rhs) {
    return ((strcmp(lhs.bootargs, rhs.bootargs) == 0) && (strcmp(lhs.image_filename, rhs.image_filename) == 0));
}

bool operator==(const cm_clint_config &lhs, const cm_clint_config &rhs) {
    return (lhs.mtimecmp == rhs.mtimecmp);
}

bool operator==(const cm_htif_config &lhs, const cm_htif_config &rhs) {
    return (lhs.fromhost == rhs.fromhost && lhs.tohost == rhs.tohost && lhs.console_getchar == rhs.console_getchar &&
        lhs.yield_manual == rhs.yield_manual && lhs.yield_automatic == rhs.yield_automatic);
}

bool operator==(const cm_machine_config &lhs, const cm_machine_config &rhs) {
    return ((lhs.processor == rhs.processor) && (lhs.rom == rhs.rom) && (lhs.ram == rhs.ram) &&
        (lhs.clint == rhs.clint) && (lhs.htif == rhs.htif));
}

std::ostream &boost_test_print_type(std::ostream &ostr, const cm_machine_config &rhs) {
    (void) rhs; // suppress 'unused param' warning
    ostr << "configs not equal" << std::endl;
    return ostr;
}

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class serialized_machine_fixture : public ordinary_machine_fixture {
public:
    serialized_machine_fixture() :
        _machine_config_path{boost::filesystem::temp_directory_path() / boost::filesystem::unique_path()} {
        char *err_msg{};
        int error_code = cm_store(_machine, _machine_config_path.string().c_str(), &err_msg);
        BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
        BOOST_CHECK_EQUAL(err_msg, nullptr);
    }

    virtual ~serialized_machine_fixture() {
        std::filesystem::remove_all(_machine_config_path.string());
    }

protected:
    boost::filesystem::path _machine_config_path;

    std::pair<uint32_t, CartesiMachine::MachineConfig> _load_config() const {
        std::ifstream ifs(_config_dir(), std::ios::binary);
        BOOST_TEST((bool) ifs);
        uint32_t version = 0;
        ifs >> version;
        version = boost::endian::little_to_native(version);
        CartesiMachine::MachineConfig proto;
        proto.ParseFromIstream(&ifs);
        return {version, proto};
    }

    void _store_config(uint32_t version, const CartesiMachine::MachineConfig &proto) const {
        std::ofstream ofs(_config_dir(), std::ios::binary);
        BOOST_TEST((bool) ofs);
        ofs << boost::endian::native_to_little(version);
        proto.SerializeToOstream(&ofs);
    }

    std::string _config_dir() const {
        return (_machine_config_path / "config.protobuf").string();
    }
};

// check that we process config version mismatch correctly
BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_invalid_config_version_test, serialized_machine_fixture) {
    auto [version, proto] = _load_config();
    _store_config(version + 1, proto);

    std::stringstream expected_err;
    expected_err << "expected config archive_version " << version << " (got " << version + 1 << ")";

    char *err_msg{};
    int error_code = cm_load_machine(_machine_config_path.c_str(), &_runtime_config, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(err_msg, expected_err.str().c_str());
    cm_delete_error_message(err_msg);
}

class store_file_fixture : public ordinary_machine_fixture {
public:
    store_file_fixture() :
        _broken_machine_path{(boost::filesystem::temp_directory_path() / boost::filesystem::unique_path()).string()} {}

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
    std::ifstream ifs(_broken_machine_path + "/config.protobuf", std::ios::out | std::fstream::binary);

    // check stored config version
    uint32_t version = 0;
    ifs >> version;
    version = boost::endian::little_to_native(version);
    BOOST_CHECK_EQUAL(version, static_cast<uint32_t>(4));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_machine_test, ordinary_machine_fixture) {
    auto f = [p = _machine_dir_path.c_str()]() {
        char *err_msg{};
        cm_store(nullptr, p, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_dir_path_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    std::string result = err_msg;
    std::string origin("error creating directory ''");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(store_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine, p = _machine_dir_path.c_str()]() { cm_store(m, p, nullptr); };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_rtc_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    error_code = cm_load_machine(_machine_dir_path.c_str(), nullptr, &_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_machine_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    auto f = [p = _machine_dir_path.c_str(), rtc = &_runtime_config]() {
        char *err_msg{};
        cm_load_machine(p, rtc, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_machine_null_error_placeholder_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);

    auto f = [p = _machine_dir_path.c_str(), rtc = &_runtime_config, m = &_machine]() {
        cm_load_machine(p, rtc, m, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(serde_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_store(_machine, _machine_dir_path.c_str(), &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_machine *restored_machine{};
    error_code = cm_load_machine(_machine_dir_path.c_str(), &_runtime_config, &restored_machine, &err_msg);
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
    auto f = []() {
        cm_hash restored_hash;
        char *err_msg{};
        cm_get_root_hash(nullptr, &restored_hash, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_null_hash_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_get_root_hash(m, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        cm_hash restored_hash;
        cm_get_root_hash(m, &restored_hash, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_machine_hash_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_hash result_hash;
    int error_code = cm_get_root_hash(_machine, &result_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), result_hash, result_hash + sizeof(cm_hash));
}

BOOST_AUTO_TEST_CASE_NOLINT(get_proof_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_merkle_tree_proof *proof{};
        cm_get_proof(nullptr, 0, 12, &proof, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_invalid_address_test, ordinary_machine_fixture) {
    char *err_msg{};
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(_machine, 1, 12, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("address not aligned to log2_size");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
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

    cm_delete_error_message(err_msg);

    // log2_word_size = 3
    error_code = cm_get_proof(_machine, 0, 2, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    result = err_msg;
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_inconsistent_tree_test, ordinary_machine_fixture) {
    char *err_msg{};
    cm_merkle_tree_proof *proof{};
    int error_code = cm_get_proof(_machine, 0, 64, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_merkle_tree_proof(proof);

    // merkle tree is always consistent now as it updates on access

    error_code = cm_get_proof(_machine, 0, 3, &proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    cm_delete_merkle_tree_proof(proof);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_null_proof_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_get_proof(m, 0, 12, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_proof_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        cm_merkle_tree_proof *proof{};
        cm_get_proof(m, 0, 12, &proof, nullptr);
    };
    monitor_system_throw(f);
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
    verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), p->root_hash,
        p->root_hash + sizeof(cm_hash));
    BOOST_CHECK_EQUAL(p->log2_root_size, static_cast<size_t>(64));
    BOOST_CHECK_EQUAL(p->sibling_hashes.count, static_cast<size_t>(52));

    cm_delete_merkle_tree_proof(p);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_word_null_machine_test) {
    auto f = []() {
        uint64_t word_value = 0;
        char *err_msg{};
        cm_read_word(nullptr, 0x100, &word_value, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_invalid_address_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    char *err_msg{};
    int error_code = cm_read_word(_machine, 0xffffffff, &word_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_UNKNOWN);

    std::string result = err_msg;
    std::string origin("Unknown error");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_null_output_test, default_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_read_word(m, 0x100, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_null_error_placeholder_test, default_machine_fixture) {
    auto f = [m = _machine]() {
        uint64_t word_value = 0;
        cm_read_word(m, 0x100, &word_value, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_word_basic_test, ordinary_machine_fixture) {
    uint64_t word_value = 0;
    char *err_msg{};
    int error_code = cm_read_word(_machine, 0x100, &word_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(word_value, static_cast<uint64_t>(0x1000));
}

BOOST_AUTO_TEST_CASE_NOLINT(read_memory_null_machine_test) {
    auto f = []() {
        std::array<uint8_t, sizeof(uint64_t)> rd{};
        char *err_msg{};
        cm_read_memory(nullptr, 0x100, rd.data(), rd.size(), &err_msg);
    };
    monitor_system_throw(f);
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

BOOST_FIXTURE_TEST_CASE_NOLINT(read_memory_null_data_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_read_memory(m, 0x80000000, nullptr, 1, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_memory_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        std::array<uint8_t, sizeof(uint64_t)> rd{};
        cm_read_memory(m, 0x100, rd.data(), 1, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_memory_null_machine_test) {
    auto f = []() {
        std::array<uint8_t, sizeof(uint64_t)> wd{};
        char *err_msg{};
        cm_write_memory(nullptr, 0x100, wd.data(), wd.size(), &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_zero_data_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_write_memory(_machine, 0x80000000, nullptr, 0, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_null_data_size_mismatch_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_write_memory(m, 0x80000000, nullptr, 1, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_memory_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        std::array<uint8_t, sizeof(uint64_t)> wd{};
        cm_write_memory(m, 0x100, wd.data(), wd.size(), nullptr);
    };
    monitor_system_throw(f);
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

    cm_delete_error_message(err_msg);
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

// NOLINTNEXTLINE
#define CHECK_READER_FAILS_ON_nullptr_MACHINE(reader_f)                                                                \
    BOOST_AUTO_TEST_CASE_NOLINT(read_##reader_f##_null_machine_test) {                                                 \
        auto f = []() {                                                                                                \
            char *err_msg{};                                                                                           \
            uint64_t out;                                                                                              \
            cm_read_##reader_f(nullptr, &out, &err_msg);                                                               \
        };                                                                                                             \
        monitor_system_throw(f);                                                                                       \
    }

// clang-format off
CHECK_READER_FAILS_ON_nullptr_MACHINE(pc)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mcycle)
CHECK_READER_FAILS_ON_nullptr_MACHINE(minstret)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mstatus)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mtvec)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mscratch)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mepc)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mcause)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mtval)
CHECK_READER_FAILS_ON_nullptr_MACHINE(misa)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mie)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mip)
CHECK_READER_FAILS_ON_nullptr_MACHINE(medeleg)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mideleg)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mcounteren)
CHECK_READER_FAILS_ON_nullptr_MACHINE(menvcfg)
CHECK_READER_FAILS_ON_nullptr_MACHINE(stvec)
CHECK_READER_FAILS_ON_nullptr_MACHINE(sscratch)
CHECK_READER_FAILS_ON_nullptr_MACHINE(sepc)
CHECK_READER_FAILS_ON_nullptr_MACHINE(scause)
CHECK_READER_FAILS_ON_nullptr_MACHINE(stval)
CHECK_READER_FAILS_ON_nullptr_MACHINE(satp)
CHECK_READER_FAILS_ON_nullptr_MACHINE(scounteren)
CHECK_READER_FAILS_ON_nullptr_MACHINE(senvcfg)
CHECK_READER_FAILS_ON_nullptr_MACHINE(ilrsc)
CHECK_READER_FAILS_ON_nullptr_MACHINE(iflags)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_tohost)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_tohost_dev)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_tohost_cmd)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_tohost_data)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_fromhost)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_ihalt)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_iconsole)
CHECK_READER_FAILS_ON_nullptr_MACHINE(htif_iyield)
CHECK_READER_FAILS_ON_nullptr_MACHINE(clint_mtimecmp)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mvendorid)
CHECK_READER_FAILS_ON_nullptr_MACHINE(marchid)
CHECK_READER_FAILS_ON_nullptr_MACHINE(mimpid)
    // clang-format on

    BOOST_AUTO_TEST_CASE_NOLINT(read_iflags_Y_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        bool out{};
        cm_read_iflags_Y(nullptr, &out, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_iflags_H_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        bool out{};
        cm_read_iflags_H(nullptr, &out, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_brkflag_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        bool out{};
        cm_read_brkflag(nullptr, &out, &err_msg);
    };
    monitor_system_throw(f);
}

// NOLINTNEXTLINE
#define CHECK_WRITER_FAILS_ON_nullptr_MACHINE(writer_f)                                                                \
    BOOST_AUTO_TEST_CASE_NOLINT(write_##writer_f##_null_machine_test) {                                                \
        auto f = []() {                                                                                                \
            char *err_msg{};                                                                                           \
            cm_write_##writer_f(nullptr, 0x1, &err_msg);                                                               \
        };                                                                                                             \
        monitor_system_throw(f);                                                                                       \
    }

// clang-format off
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(pc)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mcycle)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(minstret)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mstatus)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mtvec)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mscratch)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mepc)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mcause)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mtval)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(misa)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mie)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mip)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(medeleg)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mideleg)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(mcounteren)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(menvcfg)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(stvec)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(sscratch)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(sepc)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(scause)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(stval)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(satp)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(scounteren)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(senvcfg)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(ilrsc)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(iflags)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_tohost)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_fromhost)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_fromhost_data)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_ihalt)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_iconsole)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(htif_iyield)
CHECK_WRITER_FAILS_ON_nullptr_MACHINE(clint_mtimecmp)
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
CHECK_REGISTER_READ_WRITE(pc)
CHECK_REGISTER_READ_WRITE(mcycle)
CHECK_REGISTER_READ_WRITE(minstret)
CHECK_REGISTER_READ_WRITE(mstatus)
CHECK_REGISTER_READ_WRITE(mtvec)
CHECK_REGISTER_READ_WRITE(mscratch)
CHECK_REGISTER_READ_WRITE(mepc)
CHECK_REGISTER_READ_WRITE(mcause)
CHECK_REGISTER_READ_WRITE(mtval)
CHECK_REGISTER_READ_WRITE(misa)
CHECK_REGISTER_READ_WRITE(mie)
CHECK_REGISTER_READ_WRITE(mip)
CHECK_REGISTER_READ_WRITE(medeleg)
CHECK_REGISTER_READ_WRITE(mideleg)
CHECK_REGISTER_READ_WRITE(mcounteren)
CHECK_REGISTER_READ_WRITE(menvcfg)
CHECK_REGISTER_READ_WRITE(stvec)
CHECK_REGISTER_READ_WRITE(sscratch)
CHECK_REGISTER_READ_WRITE(sepc)
CHECK_REGISTER_READ_WRITE(scause)
CHECK_REGISTER_READ_WRITE(stval)
CHECK_REGISTER_READ_WRITE(satp)
CHECK_REGISTER_READ_WRITE(scounteren)
CHECK_REGISTER_READ_WRITE(senvcfg)
CHECK_REGISTER_READ_WRITE(ilrsc)
CHECK_REGISTER_READ_WRITE(htif_tohost)
CHECK_REGISTER_READ_WRITE(htif_fromhost)
CHECK_REGISTER_READ_WRITE(htif_ihalt)
CHECK_REGISTER_READ_WRITE(htif_iconsole)
CHECK_REGISTER_READ_WRITE(htif_iyield)
CHECK_REGISTER_READ_WRITE(clint_mtimecmp)
    // clang-format on

    BOOST_AUTO_TEST_CASE_NOLINT(set_iflags_y_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_set_iflags_Y(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(reset_iflags_y_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_reset_iflags_Y(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(set_iflags_h_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_set_iflags_H(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(iflags_read_write_complex_test, ordinary_machine_fixture) {
    uint64_t write_value = 0x0b;
    uint64_t read_value = 0;
    char *err_msg{};

    int error_code = cm_read_iflags(_machine, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x18));

    bool yflag{};
    bool hflag{};
    error_code = cm_read_iflags_Y(_machine, &yflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(!yflag);
    error_code = cm_read_iflags_H(_machine, &hflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(!hflag);

    error_code = cm_set_iflags_Y(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_iflags(_machine, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x1a));

    error_code = cm_reset_iflags_Y(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_set_iflags_H(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_iflags(_machine, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, static_cast<uint64_t>(0x19));

    error_code = cm_write_iflags(_machine, write_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_iflags(_machine, &read_value, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_value, write_value);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(brkflag_read_write_complex_test, ordinary_machine_fixture) {
    char *err_msg{};

    // set and read brkflag
    int error_code = cm_set_brkflag(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    bool brkflag{false};
    error_code = cm_read_brkflag(_machine, &brkflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(brkflag, true);

    // reset and read brkflag
    error_code = cm_reset_brkflag(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_read_brkflag(_machine, &brkflag, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(brkflag, false);
}

BOOST_AUTO_TEST_CASE_NOLINT(set_brkflag_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_set_brkflag(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(reset_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_reset_brkflag(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(ids_read_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t vendorid{};
    uint64_t archid{};
    uint64_t impid{};

    int error_code = cm_read_mvendorid(_machine, &vendorid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(vendorid, static_cast<uint64_t>(0x6361727465736920));

    error_code = cm_read_marchid(_machine, &archid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(archid, static_cast<uint64_t>(0xd));

    error_code = cm_read_mimpid(_machine, &impid, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(impid, static_cast<uint64_t>(0x1));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_tohost_read_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_write_htif_tohost(_machine, 0x1111111111111111, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t htif_dev{};
    uint64_t htif_cmd{};
    uint64_t htif_data{};
    error_code = cm_read_htif_tohost_dev(_machine, &htif_dev, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_dev, static_cast<uint64_t>(0x11));

    error_code = cm_read_htif_tohost_cmd(_machine, &htif_cmd, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_cmd, static_cast<uint64_t>(0x11));

    error_code = cm_read_htif_tohost_data(_machine, &htif_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x0000111111111111));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_htif_fromhost_read_complex_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t write_data = 0x0;
    int error_code = cm_write_htif_fromhost(_machine, write_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    write_data = 0x1111111111111111;
    error_code = cm_write_htif_fromhost_data(_machine, write_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t htif_data{};
    error_code = cm_read_htif_fromhost(_machine, &htif_data, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(htif_data, static_cast<uint64_t>(0x0000111111111111));
}

BOOST_AUTO_TEST_CASE_NOLINT(dump_pmas_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_dump_pmas(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(dump_pmas_null_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() { cm_dump_pmas(m, nullptr); };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(get_initial_config_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        const cm_machine_config *cfg{};
        cm_get_initial_config(nullptr, &cfg, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_null_output_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_get_initial_config(m, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        const cm_machine_config *cfg{};
        cm_get_initial_config(m, &cfg, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_initial_config_no_config_test, default_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        const cm_machine_config *cfg{};
        cm_get_initial_config(m, &cfg, &err_msg);
    };
    monitor_system_throw(f);
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
    auto f = []() {
        char *err_msg{};
        bool result{};
        cm_verify_dirty_page_maps(nullptr, &result, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_null_output_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_verify_dirty_page_maps(m, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        bool result{};
        cm_verify_dirty_page_maps(m, &result, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_success_test, ordinary_machine_fixture) {
    char *err_msg{};
    bool result{};
    int error_code = cm_verify_dirty_page_maps(_machine, &result, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_dirty_page_maps_default_machine_test, default_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        bool result{};
        cm_verify_dirty_page_maps(m, &result, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_flash_config_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, nullptr, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid memory range configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

class flash_drive_machine_fixture : public machine_rom_flash_simple_fixture {
public:
    flash_drive_machine_fixture() : _flash_config{}, _flash_data{"test data 1234567890"} {
        _machine_dir_path = (std::filesystem::temp_directory_path() / "661b6096c377cdc07756df488059f4407c8f4").string();
        char *err_msg{};
        cm_create_machine(&_machine_config, &_runtime_config, &_machine, &err_msg);

        size_t flash_size = 0x3c00000;
        std::string flash_file = "data.bin";
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

BOOST_FIXTURE_TEST_CASE_NOLINT(dump_pmas_basic_test, flash_drive_machine_fixture) {
    std::array dump_list{"0000000000000000--0000000000001000.bin", "0000000000001000--000000000000f000.bin",
        "0000000000010000--0000000000001000.bin", "0000000002000000--00000000000c0000.bin",
        "0000000040008000--0000000000001000.bin", "0000000080000000--0000000000100000.bin",
        "0080000000000000--0000000003c00000.bin"};

    char *err_msg{};
    int error_code = cm_dump_pmas(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    for (const auto &file : dump_list) {
        BOOST_CHECK(std::filesystem::exists(file));
        std::filesystem::remove(file);
    }
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_machine_test, flash_drive_machine_fixture) {
    auto f = [fd = &_flash_config]() {
        char *err_msg{};
        cm_replace_memory_range(nullptr, fd, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_null_error_placeholder_test, flash_drive_machine_fixture) {
    auto f = [m = _machine, fd = &_flash_config]() { cm_replace_memory_range(m, fd, nullptr); };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_pma_test, flash_drive_machine_fixture) {
    _flash_config.start = 0x9000000000000;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "Cannot replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_invalid_length_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x3c00;
    std::filesystem::resize_file(_flash_config.image_filename, _flash_config.length);

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "Cannot replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_file_length_mismatch_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x3c00;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "Cannot replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(replace_memory_range_zero_length_test, flash_drive_machine_fixture) {
    _flash_config.length = 0x0;

    char *err_msg{};
    int error_code = cm_replace_memory_range(_machine, &_flash_config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin = "Cannot replace inexistent memory range";
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
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
    auto f = []() {
        char *err_msg{};
        cm_destroy(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(destroy_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_destroy(_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
}

BOOST_AUTO_TEST_CASE_NOLINT(snapshot_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_snapshot(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(snapshot_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_snapshot(_machine, &err_msg);
    std::string result = err_msg;
    std::string origin("snapshot not supported");
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_AUTO_TEST_CASE_NOLINT(rollback_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_rollback(nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(rollback_basic_test, ordinary_machine_fixture) {
    char *err_msg = nullptr;
    int error_code = cm_rollback(_machine, &err_msg);
    std::string result = err_msg;
    std::string origin("do_rollback is not supported");
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_AUTO_TEST_CASE_NOLINT(read_x_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        uint64_t val{};
        cm_read_x(nullptr, 4, &val, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_x_null_output_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_read_x(m, 4, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_x_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        uint64_t val{};
        cm_read_x(m, 4, &val, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_x_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_write_x(nullptr, 4, 0, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_x_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() { cm_write_x(m, 4, 0, nullptr); };
    monitor_system_throw(f);
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

BOOST_AUTO_TEST_CASE_NOLINT(read_csr_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        uint64_t val{};
        cm_read_csr(nullptr, CM_PROC_MCYCLE, &val, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_csr_null_output_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_read_csr(m, CM_PROC_MCYCLE, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_csr_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        uint64_t val{};
        cm_read_csr(m, CM_PROC_MCYCLE, &val, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_AUTO_TEST_CASE_NOLINT(write_csr_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_write_csr(nullptr, CM_PROC_MCYCLE, 3, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(write_csr_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() { cm_write_csr(m, CM_PROC_MCYCLE, 3, nullptr); };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(read_write_csr_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    uint64_t csr_origin = 42;
    uint64_t csr_read{};

    int error_code = cm_write_csr(_machine, CM_PROC_MCYCLE, csr_origin, &err_msg);
    ;
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_read_csr(_machine, CM_PROC_MCYCLE, &csr_read, &err_msg);
    ;
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(csr_origin, csr_read);

    BOOST_CHECK_EQUAL(static_cast<uint64_t>(0x100), cm_get_csr_address(CM_PROC_PC));
}

BOOST_AUTO_TEST_CASE_NOLINT(verify_merkle_tree_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        bool ret{};
        cm_verify_merkle_tree(nullptr, &ret, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_null_output_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        char *err_msg{};
        cm_verify_merkle_tree(m, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() {
        bool ret{};
        cm_verify_merkle_tree(m, &ret, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_merkle_tree_basic_test, ordinary_machine_fixture) {
    char *err_msg{};
    bool ret{};
    int error_code = cm_verify_merkle_tree(_machine, &ret, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    BOOST_CHECK(ret);
}

class access_log_machine_fixture : public ordinary_machine_fixture {
public:
    access_log_machine_fixture() : _access_log{}, _log_type{true, true} {}

    ~access_log_machine_fixture() = default;
    access_log_machine_fixture(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture(access_log_machine_fixture &&other) noexcept = delete;
    access_log_machine_fixture &operator=(const access_log_machine_fixture &other) = delete;
    access_log_machine_fixture &operator=(access_log_machine_fixture &&other) noexcept = delete;

protected:
    cm_access_log *_access_log;
    cm_access_log_type _log_type;
};

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_access_log_null_log_test, default_machine_fixture) {
    char *err_msg{};
    int error_code = cm_verify_access_log(nullptr, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid access log");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_access_log_null_rt_config_test, access_log_machine_fixture) {
    char *err_msg{};
    int error_code = cm_step(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_verify_access_log(_access_log, nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_access_log_null_error_placeholder_test, access_log_machine_fixture) {
    char *err_msg{};
    int error_code = cm_step(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto f = [l = _access_log, rc = &_runtime_config]() { cm_verify_access_log(l, rc, false, nullptr); };
    monitor_system_throw(f);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_machine_test, access_log_machine_fixture) {
    auto f = [l = &_access_log, lt = _log_type]() {
        char *err_msg{};
        cm_step(nullptr, lt, false, l, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_access_log_test, access_log_machine_fixture) {
    auto f = [m = _machine, lt = _log_type]() {
        char *err_msg{};
        cm_step(m, lt, false, nullptr, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_null_error_placeholder_test, access_log_machine_fixture) {
    auto f = [m = _machine, l = &_access_log, lt = _log_type]() { cm_step(m, lt, false, l, nullptr); };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_state_transition_null_hash0_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash1;
    int error_code = cm_verify_state_transition(nullptr, _access_log, &hash1, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid hash");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_state_transition_null_hash1_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    int error_code = cm_verify_state_transition(&hash0, _access_log, nullptr, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid hash");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_state_transition_null_access_log_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    cm_hash hash1;
    int error_code = cm_verify_state_transition(&hash0, nullptr, &hash1, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid access log");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_state_transition_null_rt_config_test, access_log_machine_fixture) {
    char *err_msg{};
    int error_code = cm_step(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    cm_hash hash0;
    cm_hash hash1;
    error_code = cm_verify_state_transition(&hash0, _access_log, &hash1, nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(verify_state_transition_null_error_placeholder_test, access_log_machine_fixture) {
    auto f = [l = _access_log, rc = &_runtime_config]() {
        cm_hash hash0;
        cm_hash hash1;
        cm_verify_state_transition(&hash0, l, &hash1, rc, false, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_complex_test, access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0;
    cm_hash hash1;

    int error_code = cm_get_root_hash(_machine, &hash0, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_step(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_verify_access_log(_access_log, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    error_code = cm_get_root_hash(_machine, &hash1, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    error_code = cm_verify_state_transition(&hash0, _access_log, &hash1, &_runtime_config, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_delete_access_log(_access_log);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(step_hash_test, access_log_machine_fixture) {
    char *err_msg{};

    int error_code = cm_step(_machine, _log_type, false, &_access_log, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_hash hash1;
    error_code = cm_get_root_hash(_machine, &hash1, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);

    auto verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash1, hash1 + sizeof(cm_hash));

    cm_delete_access_log(_access_log);
}

BOOST_AUTO_TEST_CASE_NOLINT(machine_run_null_machine_test) {
    auto f = []() {
        char *err_msg{};
        cm_machine_run(nullptr, 1000, &err_msg);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_null_error_placeholder_test, ordinary_machine_fixture) {
    auto f = [m = _machine]() { cm_machine_run(m, 1000, nullptr); };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_1000_cycle_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_machine_run(_machine, 1000, &err_msg);
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

    auto verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_1000, hash_1000 + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_to_past_test, ordinary_machine_fixture) {
    uint64_t cycle_num = 1000;
    uint64_t cycle_num_to_past = 100;

    char *err_msg{};
    int error_code = cm_machine_run(_machine, cycle_num, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    uint64_t read_mcycle{};
    error_code = cm_read_mcycle(_machine, &read_mcycle, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_CHECK_EQUAL(read_mcycle, cycle_num);

    error_code = cm_machine_run(_machine, cycle_num_to_past, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);

    std::string result = err_msg;
    std::string origin("mcycle is past");
    BOOST_CHECK_EQUAL(origin, result);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_run_long_cycle_test, ordinary_machine_fixture) {
    char *err_msg{};
    int error_code = cm_machine_run(_machine, 600000, &err_msg);
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

    auto verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), hash_end, hash_end + sizeof(cm_hash));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(machine_verify_merkle_tree_root_updates_test, ordinary_machine_fixture) {
    char *err_msg{};

    cm_hash start_hash;
    int error_code = cm_get_root_hash(_machine, &start_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    auto verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_hash, start_hash + sizeof(cm_hash));

    error_code = cm_machine_run(_machine, 1000, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_hash end_hash;
    error_code = cm_get_root_hash(_machine, &end_hash, &err_msg);
    BOOST_REQUIRE_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    verification = get_verification_root_hash(_machine);
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
    verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), start_proof->root_hash,
        start_proof->root_hash + sizeof(cm_hash));
    cm_delete_merkle_tree_proof(start_proof);

    error_code = cm_machine_run(_machine, 1000, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);

    cm_merkle_tree_proof *end_proof{};
    error_code = cm_get_proof(_machine, 0, 12, &end_proof, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    verification = calculate_proof_root_hash(end_proof);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_proof->root_hash,
        end_proof->root_hash + sizeof(cm_hash));
    verification = get_verification_root_hash(_machine);
    BOOST_CHECK_EQUAL_COLLECTIONS(verification.begin(), verification.end(), end_proof->root_hash,
        end_proof->root_hash + sizeof(cm_hash));
    cm_delete_merkle_tree_proof(end_proof);
}

// GRPC machine tests

class grpc_machine_fixture : public machine_rom_flash_simple_fixture {
public:
    grpc_machine_fixture() : m_stub{} {
        char *err_msg{};
        int result = cm_create_grpc_machine_stub("127.0.0.1:5001", "127.0.0.1:5002", &m_stub, &err_msg);
        BOOST_CHECK_EQUAL(result, CM_ERROR_OK);
        BOOST_CHECK_EQUAL(err_msg, nullptr);
    }
    virtual ~grpc_machine_fixture() {
        cm_delete_grpc_machine_stub(m_stub);
    }
    grpc_machine_fixture(const grpc_machine_fixture &) = delete;
    grpc_machine_fixture(grpc_machine_fixture &&) = delete;
    grpc_machine_fixture &operator=(const grpc_machine_fixture &) = delete;
    grpc_machine_fixture &operator=(grpc_machine_fixture &&) = delete;

protected:
    cm_grpc_machine_stub *m_stub;
};

static bool wait_for_server(cm_grpc_machine_stub *stub, int retries = 10) {
    for (int i = 0; i < retries; i++) {
        const cm_semantic_version *version{};
        char *err_msg{};
        int status = cm_grpc_get_semantic_version(stub, &version, &err_msg);
        if (status == CM_ERROR_OK) {
            cm_delete_semantic_version(version);
            return true;
        } else {
            cm_delete_error_message(err_msg);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return false;
}

class grpc_machine_fixture_with_server : public grpc_machine_fixture {
public:
    grpc_machine_fixture_with_server() {
        boost::process::spawn(boost::process::search_path("remote-cartesi-machine"), "127.0.0.1:5001", m_server_group);
        BOOST_CHECK(wait_for_server(m_stub));
    }
    ~grpc_machine_fixture_with_server() override = default;
    grpc_machine_fixture_with_server(const grpc_machine_fixture_with_server &) = delete;
    grpc_machine_fixture_with_server(grpc_machine_fixture_with_server &&) = delete;
    grpc_machine_fixture_with_server &operator=(const grpc_machine_fixture_with_server &) = delete;
    grpc_machine_fixture_with_server &operator=(grpc_machine_fixture_with_server &&) = delete;

protected:
    boost::process::group m_server_group;
};

class grpc_access_log_machine_fixture : public grpc_machine_fixture {
public:
    grpc_access_log_machine_fixture() : _access_log{}, _log_type{true, true} {}
    ~grpc_access_log_machine_fixture() override = default;
    grpc_access_log_machine_fixture(const grpc_access_log_machine_fixture &) = delete;
    grpc_access_log_machine_fixture(grpc_access_log_machine_fixture &&) = delete;
    grpc_access_log_machine_fixture &operator=(const grpc_access_log_machine_fixture &) = delete;
    grpc_access_log_machine_fixture &operator=(grpc_access_log_machine_fixture &&) = delete;

protected:
    cm_access_log *_access_log;
    cm_access_log_type _log_type;
};

BOOST_AUTO_TEST_CASE_NOLINT(create_grpc_machine_stub_wrong_address_test) {
    char *err_msg{};
    cm_grpc_machine_stub *stub{};
    int error_code = cm_create_grpc_machine_stub("addr", "rdda", &stub, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    std::string result = err_msg;
    std::string origin("unable to create checkin server");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_AUTO_TEST_CASE_NOLINT(create_grpc_machine_stub_no_server_test) {
    char *err_msg{};
    cm_grpc_machine_stub *stub{};
    int error_code = cm_create_grpc_machine_stub("127.0.0.2:5001", "127.0.0.1:5002", &stub, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    cm_delete_grpc_machine_stub(stub);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_null_config_test, grpc_machine_fixture) {
    char *err_msg{};
    cm_machine *new_machine{};
    int error_code = cm_create_grpc_machine(m_stub, nullptr, &_runtime_config, &new_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine configuration");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
    cm_delete_machine(new_machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_null_rt_config_test, grpc_machine_fixture) {
    char *err_msg{};
    cm_machine *new_machine{};
    int error_code = cm_create_grpc_machine(m_stub, &_machine_config, nullptr, &new_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
    cm_delete_machine(new_machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_wrong_address_test, grpc_machine_fixture) {
    char *err_msg{};
    cm_grpc_machine_stub *stub{};
    int error_code = cm_create_grpc_machine_stub("addr", "rdda", &stub, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    BOOST_CHECK_EQUAL(stub, nullptr);
    std::string result = err_msg;
    std::string origin("unable to create checkin server");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_no_server_test, grpc_machine_fixture) {
    char *err_msg{};
    cm_machine *new_machine{};
    int error_code = cm_create_grpc_machine(m_stub, &_machine_config, &_runtime_config, &new_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);

    std::string result = err_msg;
    std::string origin("failed to connect to all addresses");
    BOOST_CHECK_MESSAGE(result.find(origin) != std::string::npos, "unexpected error message: " << result);
    cm_delete_error_message(err_msg);
    cm_delete_machine(new_machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_basic_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    cm_machine *machine{};
    int error_code = cm_create_grpc_machine(m_stub, &_machine_config, &_runtime_config, &machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    if (err_msg != nullptr) {
        printf("Error creating grpc machine: %s\n", err_msg);
        cm_delete_error_message(err_msg);
    }
    cm_delete_machine(machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(create_grpc_machine_null_error_placeholder_test, grpc_machine_fixture) {
    auto f = [this]() {
        cm_machine *new_machine{};
        cm_create_grpc_machine(m_stub, &_machine_config, &_runtime_config, &new_machine, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(get_grpc_machine_basic_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    cm_machine *machine{};
    int error_code = cm_create_grpc_machine(m_stub, &_machine_config, &_runtime_config, &machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    cm_machine *machine_2{};
    error_code = cm_get_grpc_machine(m_stub, &machine_2, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    // Destroy the machine with the second handler and check whether the
    // original machine was actually deleted as well
    error_code = cm_destroy(machine_2, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    error_code = cm_destroy(machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(err_msg, nullptr);
    cm_delete_machine(machine_2);
    cm_delete_machine(machine);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_grpc_machine_null_dir, grpc_machine_fixture_with_server) {
    char *err_msg{};
    cm_machine *new_machine{};
    int error_code = cm_load_grpc_machine(m_stub, nullptr, &_runtime_config, &new_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_RUNTIME_ERROR);
    std::string result = err_msg;
    std::string origin("unable to open '/config.protobuf' for reading");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_grpc_machine_null_rt_config_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    cm_machine *new_machine{};
    int error_code = cm_load_grpc_machine(m_stub, "some_dir", nullptr, &new_machine, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid machine runtime configuration");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(load_grpc_machine_null_error_placeholder_test, grpc_machine_fixture) {
    auto f = [this]() {
        cm_machine *new_machine{};
        cm_load_grpc_machine(m_stub, "some_dir", &_runtime_config, &new_machine, nullptr);
    };
    monitor_system_throw(f);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_get_default_config_basic_test, grpc_machine_fixture_with_server) {
    const cm_machine_config *config{};
    char *err_msg{};
    int error_code = cm_grpc_get_default_config(m_stub, &config, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    if (err_msg != nullptr) {
        printf("Error getting default config: %s\n", err_msg);
    }
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    cm_delete_machine_config(config);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_get_x_address_basic_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    uint64_t val{};
    int error_code = cm_grpc_get_x_address(m_stub, 5, &val, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    if (err_msg != nullptr) {
        printf("Error getting x address: %s\n", err_msg);
    }
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(val, static_cast<uint64_t>(40));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_get_csr_address_basic_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    uint64_t val{};
    int error_code = cm_grpc_get_csr_address(m_stub, CM_PROC_MIMPID, &val, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    if (err_msg != nullptr) {
        printf("Error getting csr address: %s\n", err_msg);
    }
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    BOOST_REQUIRE_EQUAL(val, static_cast<uint64_t>(280));
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_get_version_wrong_addr_test, grpc_machine_fixture_with_server) {
    char *err_msg{};
    const cm_semantic_version *version{};
    int error_code = cm_grpc_get_semantic_version(m_stub, &version, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_OK);
    if (err_msg != nullptr) {
        printf("Error getting semantic version: %s\n", err_msg);
    }
    BOOST_REQUIRE_EQUAL(err_msg, nullptr);
    cm_delete_semantic_version(version);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_verify_state_transition_null_hash0_test, grpc_access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash1;
    int error_code = cm_grpc_verify_state_transition(m_stub, nullptr, _access_log, &hash1, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid hash");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_verify_state_transition_null_hash1_test, grpc_access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0{};
    int error_code = cm_grpc_verify_state_transition(m_stub, &hash0, _access_log, nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid hash");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_verify_state_transition_null_ljog_test, grpc_access_log_machine_fixture) {
    char *err_msg{};
    cm_hash hash0{};
    cm_hash hash1{};
    int error_code = cm_grpc_verify_state_transition(m_stub, &hash0, nullptr, &hash1, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid access log");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}

BOOST_FIXTURE_TEST_CASE_NOLINT(grpc_verify_access_log_null_log_test, grpc_access_log_machine_fixture) {
    char *err_msg{};
    int error_code = cm_grpc_verify_access_log(m_stub, nullptr, false, &err_msg);
    BOOST_CHECK_EQUAL(error_code, CM_ERROR_INVALID_ARGUMENT);
    std::string result = err_msg;
    std::string origin("Invalid access log");
    BOOST_CHECK_EQUAL(origin, result);
    cm_delete_error_message(err_msg);
}
