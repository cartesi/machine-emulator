--[[
Test suite for runtime console input/output configuration.
]]

local lester = require("cartesi.third-party.lester")
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local tabular = require("cartesi.tabular")
local utils = require("cartesi.utils")
local tests_util = require("cartesi.tests.util")
local has_posix, unistd = pcall(require, "posix.unistd")

local function create_remote_machine(...)
    local jsonrpc = require("cartesi.jsonrpc")
    return jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(...)
end

local function create_local_machine(...)
    return cartesi.machine(...)
end

describe("runtime console io", function()
    for _, desc in ipairs({
        {
            name = "local",
            create_machine = create_local_machine,
        },
        {
            name = "remote",
            create_machine = create_remote_machine,
        },
    }) do
        local create_machine = desc.create_machine
        describe(desc.name, function()
            local base_machine_config = {
                ram = {
                    length = 0x10000,
                    backing_store = {
                        data_filename = tests_util.tests_path .. "htif_console.bin",
                    },
                },
            }
            local interactive_machine_config = tabular.deep_copy_and_merge(base_machine_config, {
                processor = {
                    registers = {
                        iunrep = 1,
                        htif = {
                            iconsole = cartesi.HTIF_CONSOLE_CMD_PUTCHAR_MASK | cartesi.HTIF_CONSOLE_CMD_GETCHAR_MASK,
                        },
                    },
                },
            })

            it("should fail when attempting to use unsupported redirect configurations", function()
                local machine <close> = create_machine(base_machine_config)
                expect.fail(function()
                    machine:read_console_output()
                end, "console output destination is not using a buffer")
                expect.fail(function()
                    machine:read_console_output(0)
                end, "console output destination is not using a buffer")
                expect.fail(function()
                    machine:write_console_input()
                end, "console input source is not using a buffer")
                expect.fail(function()
                    machine:write_console_input("x")
                end, "console input source is not using a buffer")
                expect.fail(function()
                    local _ <close> = create_machine(base_machine_config, {
                        console = {
                            output_buffer_size = 0,
                        },
                    })
                end, "console output buffer size must be greater than 0")
                expect.fail(function()
                    local _ <close> = create_machine(base_machine_config, {
                        console = {
                            input_buffer_size = 0,
                        },
                    })
                end, "console input buffer size must be greater than 0")
                expect.fail(function()
                    machine:set_runtime_config({
                        console = {
                            output_buffer_size = 2048,
                        },
                    })
                end, "shrinking runtime console output buffer size is not allowed")
                expect.fail(function()
                    machine:set_runtime_config({
                        console = {
                            input_buffer_size = 2048,
                        },
                    })
                end, "shrinking runtime console input buffer size is not allowed")
            end)

            it("should redirect console output to null", function()
                local machine <close> =
                    create_machine(base_machine_config, { console = { output_destination = "to_null" } })
                machine:run()
            end)

            it("should redirect console output to stdout", function()
                local machine <close> =
                    create_machine(base_machine_config, { console = { output_destination = "to_stdout" } })
                machine:run()
            end)

            it("should redirect console output to stderr", function()
                local machine <close> =
                    create_machine(base_machine_config, { console = { output_destination = "to_stderr" } })
                machine:run()
            end)

            it("should redirect console output to a file", function()
                local _ <close>, out_filename = filesystem.write_scope_temp_file("")
                local machine <close> = create_machine(
                    base_machine_config,
                    { console = { output_destination = "to_file", output_filename = out_filename } }
                )
                machine:run()
                expect.equal(filesystem.read_file(out_filename), "CTSI\n")
            end)

            if has_posix and desc.name == "local" then
                it("should redirect console output to a file descriptor", function()
                    local out_r, out_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(out_r)
                        unistd.close(out_w)
                    end)
                    local machine <close> = create_machine(
                        base_machine_config,
                        { console = { output_destination = "to_fd", output_fd = out_w } }
                    )
                    machine:run()
                    expect.equal(unistd.read(out_r, 1024), "CTSI\n")
                end)

                it("should fail when redirecting console output to a read-only pipe", function()
                    local out_r, out_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(out_r)
                        if out_w then
                            unistd.close(out_w)
                        end
                    end)
                    local machine <close> = create_machine(
                        base_machine_config,
                        { console = { output_destination = "to_fd", output_fd = out_r } }
                    )
                    unistd.close(out_w)
                    out_w = nil
                    expect.fail(function()
                        machine:run()
                    end, "console output flush failed")
                end)
            end

            it("should redirect console output to an internal buffer", function()
                local machine <close> = create_machine(
                    base_machine_config,
                    { console = { output_destination = "to_buffer", output_flush_mode = "when_full" } }
                )
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(0), 5)
                expect.equal(machine:read_console_output(), "CTSI\n")
                expect.equal(machine:read_console_output(0), 0)
                expect.equal(machine:read_console_output(), "")
            end)

            it("should read partial console output", function()
                local machine <close> = create_machine(
                    base_machine_config,
                    { console = { output_destination = "to_buffer", output_flush_mode = "when_full" } }
                )
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(0), 5)
                expect.equal(machine:read_console_output(3), "CTS")
                expect.equal(machine:read_console_output(0), 2)
                expect.equal(machine:read_console_output(1), "I")
                expect.equal(machine:read_console_output(0), 1)
                expect.equal(machine:read_console_output(), "\n")
            end)

            it("should flush console output when buffer is full", function()
                local machine <close> = create_machine(base_machine_config, {
                    console = {
                        output_destination = "to_buffer",
                        output_buffer_size = 4,
                        output_flush_mode = "when_full",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                expect.equal(machine:read_console_output(), "CTSI")
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(), "\n")
            end)

            it("should flush console output when buffer is full before a new line", function()
                local machine <close> = create_machine(base_machine_config, {
                    console = {
                        output_destination = "to_buffer",
                        output_buffer_size = 4,
                        output_flush_mode = "every_line",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                expect.equal(machine:read_console_output(), "CTSI")
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                expect.equal(machine:read_console_output(), "\n")
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
            end)

            it("should flush console output every new line", function()
                local machine <close> = create_machine(
                    base_machine_config,
                    { console = { output_destination = "to_buffer", output_flush_mode = "every_line" } }
                )
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                expect.equal(machine:read_console_output(), "CTSI\n")
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
            end)

            it("should flush console output every new character", function()
                local machine <close> = create_machine(base_machine_config, {
                    console = {
                        output_destination = "to_buffer",
                        output_buffer_size = 4,
                        output_flush_mode = "every_char",
                    },
                })
                local expected_chars = { "C", "T", "S", "I", "\n" }
                for _, expected_ch in ipairs(expected_chars) do
                    expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                    expect.equal(machine:read_console_output(), expected_ch)
                end
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
            end)

            it("should redirect console input from null", function()
                local machine <close> = create_machine(interactive_machine_config, {
                    console = {
                        input_source = "from_null",
                        output_destination = "to_buffer",
                        output_flush_mode = "when_full",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                -- htif_console will write nothing to the console in case getchar doesn't returns "CTSI"
                expect.equal(machine:read_console_output(), "")
            end)

            it("should redirect console input from a buffer", function()
                local machine <close> = create_machine(interactive_machine_config, {
                    console = {
                        input_source = "from_buffer",
                        output_destination = "to_buffer",
                        output_flush_mode = "when_full",
                    },
                })
                expect.equal(machine:write_console_input(""), 0)
                expect.equal(machine:write_console_input("CTSI"), 4)
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_INPUT)
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(), "CTSI\n")
            end)

            it("should redirect console input from a file", function()
                local _ <close>, in_filename = filesystem.write_scope_temp_file("CTSI")
                local machine <close> = create_machine(interactive_machine_config, {
                    console = {
                        input_source = "from_file",
                        input_filename = in_filename,
                        output_destination = "to_buffer",
                        output_flush_mode = "when_full",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(), "CTSI\n")
            end)

            it("should redirect console input from a file until EOF", function()
                local _ <close>, in_filename = filesystem.write_scope_temp_file("CTS")
                local machine <close> = create_machine(interactive_machine_config, {
                    console = {
                        input_source = "from_file",
                        input_filename = in_filename,
                        output_destination = "to_buffer",
                        output_flush_mode = "when_full",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                expect.equal(machine:read_console_output(), "CTS")
            end)

            if has_posix and desc.name == "local" then
                it("should redirect console input from a stdin", function()
                    -- readirect stdin to a new pipe
                    local in_r, in_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(in_r)
                        unistd.close(in_w)
                    end)
                    local old_stdin = assert(unistd.dup(unistd.STDIN_FILENO))
                    assert(unistd.dup2(in_r, unistd.STDIN_FILENO))
                    local _ <close> = utils.scope_exit(function()
                        unistd.dup2(old_stdin, unistd.STDIN_FILENO)
                        unistd.close(old_stdin)
                    end)
                    assert(unistd.write(in_w, "CTSI"))
                    -- test
                    local machine <close> = create_machine(interactive_machine_config, {
                        console = {
                            input_source = "from_stdin",
                            output_destination = "to_buffer",
                            output_flush_mode = "when_full",
                        },
                    })
                    expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                    expect.equal(machine:read_console_output(), "CTSI\n")
                end)

                it("should redirect console input from a file descriptor", function()
                    local in_r, in_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(in_r)
                        unistd.close(in_w)
                    end)
                    assert(unistd.write(in_w, "CTSI"))
                    local machine <close> = create_machine(interactive_machine_config, {
                        console = {
                            input_source = "from_fd",
                            input_fd = in_r,
                            output_destination = "to_buffer",
                            output_flush_mode = "when_full",
                        },
                    })
                    expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                    expect.equal(machine:read_console_output(), "CTSI\n")
                end)

                it("should fail when redirecting console input to a write-only pipe", function()
                    expect.fail(function()
                        local in_r, in_w = assert(unistd.pipe())
                        local _ <close> = utils.scope_exit(function()
                            if in_r then
                                unistd.close(in_r)
                            end
                            unistd.close(in_w)
                        end)
                        local machine <close> = create_machine(interactive_machine_config, {
                            console = {
                                input_source = "from_fd",
                                input_fd = in_w,
                            },
                        })
                        unistd.close(in_r)
                        in_r = nil
                        machine:run()
                    end, "console input refill failed")
                end)

                it("should redirect console input from a file descriptor until EOF", function()
                    local in_r, in_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(in_r)
                        unistd.close(in_w)
                    end)
                    assert(unistd.write(in_w, "CTS"))
                    assert(unistd.close(in_w))
                    local machine <close> = create_machine(interactive_machine_config, {
                        console = {
                            input_source = "from_fd",
                            input_fd = in_r,
                            output_destination = "to_buffer",
                            output_flush_mode = "when_full",
                        },
                    })
                    expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
                    expect.equal(machine:read_console_output(), "CTS")
                end)
            end

            it("should redirect console input/output at runtime", function()
                local machine <close> = create_machine(interactive_machine_config, {
                    console = {
                        output_destination = "to_buffer",
                        output_flush_mode = "every_char",
                        output_buffer_size = 1024,
                        input_source = "from_buffer",
                        input_buffer_size = 4,
                    },
                })
                expect.equal(machine:write_console_input(), 4)
                expect.equal(machine:write_console_input("CT"), 2)
                expect.equal(machine:write_console_input(), 2)
                expect.equal(machine:run(), cartesi.BREAK_REASON_CONSOLE_OUTPUT)
                expect.equal(machine:read_console_output(0), 1)
                expect.equal(machine:read_console_output(), "C")
                expect.equal(machine:write_console_input("SIXX"), 3) -- 1 was consumed, can add a most 3
                expect.equal(machine:write_console_input(), 0)
                machine:set_runtime_config({
                    console = {
                        input_source = "from_null",
                        output_destination = "to_null",
                    },
                })
                expect.equal(machine:run(), cartesi.BREAK_REASON_HALTED)
            end)
        end)
    end
end)
