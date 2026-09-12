#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0
--
-- Transpiles machine-emulator's uarch C++ sources to Solidity.
-- Targets the binary step log replayer: produces code that operates on a
-- `StepLog.Context memory a` and calls bridge functions in `StateAccess`.

local lpeg = require("lpeg")
local P, R, S, V, C, Cs = lpeg.P, lpeg.R, lpeg.S, lpeg.V, lpeg.C, lpeg.Cs

local M = {}

M.LICENSE_BANNER = [=[// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//]=]

local ws    = S(" \t")
local nl    = P("\n")
local ws_nl = ws + nl
local ident = (R("az","AZ") + P("_")) * (R("az","AZ","09") + P("_"))^0
-- Lexical tokens shared by the passes that must skip over strings and comments.
local string_literal = P('"') * (P('\\') * 1 + (1 - P('"')))^0 * P('"')
local line_comment   = P("//") * (1 - nl)^0
local block_comment  = P("/*") * (1 - P("*/"))^0 * P("*/")

local function extract_namespace_body(src)
    -- Skip strings and comments so a brace inside one is not taken for a namespace delimiter.
    local inner = (string_literal + line_comment + block_comment + (1 - S("{}")) + V(1))^0
    local pattern = (1 - P("namespace cartesi"))^0
                  * P("namespace cartesi") * ws^0
                  * P{ "{" * C(inner) * "}" }
    return assert(pattern:match(src), "namespace cartesi not found")
end

local function strip_cpp_only(src)
    local rest_of_line    = (1 - nl)^0 * nl
    -- Skip strings and comments so a ';' inside one is not taken for the statement terminator.
    local until_semicolon = (string_literal + line_comment + (1 - P(";")))^0 * P(";") * ws^0 * nl^-1
    local pattern = Cs((
          (ws^0 * P("template") * ws^0 * P("<") * (1 - P(">"))^0 * P(">") * ws^0) / ""
        + (ws^0 * P("template") * until_semicolon) / ""
        + (ws^0 * P("[[maybe_unused]]") * until_semicolon) / ""
        + (ws^0 * P("(void)") * ws_nl^1 * P("note") * until_semicolon) / ""
        + (ws^0 * P("// Explicit instantiat") * rest_of_line) / ""
        + (P("constexpr") * ws^1) / ""
        + 1
    )^0)
    return pattern:match(src)
end

local function convert_fn_signatures(src, entrypoint)
    local static_inline = P("static") * ws^1 * P("inline") * ws^1
    local leading_ws    = C(ws^0)
    local return_type   = C(ident)
    local func_name     = C(ident)
    local param_list    = P("(") * C((1 - P(")"))^0) * P(")")
    local open_brace    = P("{")
    local fn_sig = leading_ws * static_inline^-1
                 * return_type * ws^1 * func_name
                 * ws^0 * param_list
                 * ws^0 * open_brace
    local rewrite = fn_sig / function(indent, ret_type, name, params)
        -- C++ template-parameter accessor types to the concrete Solidity type.
        -- Variable name `a` is preserved so the body's `readWord(a, ...)` calls still parse.
        params = params:gsub("const%s+StateAccess%s+a",            "StepLog.Context memory a")
        params = params:gsub("StateAccess%s+&a",                   "StepLog.Context memory a")
        params = params:gsub("const%s+UarchState%s+a",                  "StepLog.Context memory a")
        params = params:gsub("UarchState%s+&a",                         "StepLog.Context memory a")
        params = params:gsub("STATE_ACCESS%s+a",                        "StepLog.Context memory a")
        -- send_cmio_response: rewrite the C++ `bytes data` / `const unsigned char *data`
        -- parameter to Solidity calldata bytes; the verifier computes the padded-data
        -- Merkle hash on-chain.
        params = params:gsub("bytes%s+data",                      "bytes calldata data")
        params = params:gsub("const%s+unsigned%s+char%s+%*data",  "bytes calldata data")
        -- Rename only the public entry points; internal helpers keep their C++ names
        -- so grep-trace from Solidity back to C++ works.
        local fn_renames = {
            uarch_step         = "uarchStep",
            uarch_reset_state  = "uarchResetState",
            send_cmio_response = "sendCmioResponse",
        }
        name = fn_renames[name] or name
        local visibility = name == entrypoint and "internal" or "private"
        local ret = ret_type ~= "void" and (" returns (" .. ret_type .. ")") or ""
        return indent .. "function " .. name .. "(" .. params .. ") " .. visibility .. " pure" .. ret .. " {"
    end
    return Cs((rewrite + 1)^0):match(src)
end

local function transform_code(src, fn)
    local not_string_or_comment = (1 - string_literal - line_comment)^1
    local code = C(not_string_or_comment) / fn
    return Cs((string_literal + line_comment + code)^0):match(src)
end

local function cpp_to_solidity_syntax(src)
    return transform_code(src, function(code)
        code = code:gsub("const%s+(u?int%d+)", "%1")
        code = code:gsub("::", ".")
        code = code:gsub("UINT64_MAX", "type(uint64).max")
        return code
    end)
end

-- The transpiler does only mechanical rewrites; it does NOT translate shift width,
-- integer width, or signedness. The uarch C++ sources are written in a Solidity-
-- compatible dialect where those operations go through uarch-solidity-compat.hpp
-- helpers (uint32ShiftLeft, int32ShiftRight, ...) and use the intN/uintN aliases.
-- This guard fails transpilation if a raw shift on a non-literal operand, or a native
-- fixed-width C++ type (intN_t/uintN_t), reaches the body: either would silently emit
-- Solidity whose overflow/sign/width semantics diverge from the C++/RISC0 replayers.
-- Constant-only shifts in decode masks, e.g. (0x7f << 25), are allowed because both
-- operands are literals.
local function assert_solidity_dialect(body)
    local function is_int_literal(tok)
        return tok ~= "" and (tok:match("^%d+$") ~= nil or tok:match("^0[xX]%x+$") ~= nil)
    end
    transform_code(body, function(code)
        local native = code:match("%f[%w]u?int%d+_t%f[%W]")
        if native then
            error("transpile dialect guard: native C++ type '" .. native
                .. "' reached the transpiled body. Use the Solidity-dialect alias (intN/uintN) "
                .. "routed through uarch-solidity-compat.hpp, not a native " .. native .. ".")
        end
        for lhs, op, rhs in code:gmatch("([%w_]*)%s*([<>][<>])%s*([%w_]*)") do
            if (op == "<<" or op == ">>") and not (is_int_literal(lhs) and is_int_literal(rhs)) then
                error("transpile dialect guard: raw shift '"
                    .. (lhs == "" and "<expr>" or lhs) .. " " .. op .. " "
                    .. (rhs == "" and "<expr>" or rhs)
                    .. "' on a non-literal operand. The transpiler does not translate shift "
                    .. "width/semantics; route variable shifts through a uarch-solidity-compat.hpp "
                    .. "helper (e.g. uint32ShiftLeft). Only constant decode masks like (0x7f << 25) "
                    .. "are allowed.")
            end
        end
        return code
    end)
end

local function prefix_names(src, names, prefix)
    return transform_code(src, function(code)
        for name in pairs(names) do
            code = code:gsub("%f[%w]" .. name .. "%f[%W]", prefix .. name)
        end
        return code
    end)
end

local function extract_names(src, pattern)
    local t = {}
    for name in src:gmatch(pattern) do t[name] = true end
    return t
end

-- Blank parameter names that are unused in the body, to avoid "unused parameter" warnings in Solidity.
local function blank_unused_param_names(src)
    local body = P{ "{" * (string_literal + line_comment + block_comment + (1 - S("{}")) + V(1))^0 * "}" }
    local fn = C(P("function") * ws_nl^1 * ident * ws_nl^0 * P("(")) -- prefix incl '('
             * C((1 - P(")"))^0)                               -- params
             * C(P(")") * (1 - P("{"))^0)                      -- ') visibility pure ...'
             * C(body)

    local function strip_noncode(s)
        return (s:gsub("/%*.-%*/", " "):gsub("//[^\n]*", " "):gsub('".-"', " "))
    end

    local function rewrite(prefix, params, suffix, fn_body)
        local code = strip_noncode(fn_body)
        local kept = {} -- params to keep, after dropping unused names
        for param in (params .. ","):gmatch("%s*(.-)%s*,") do
            if param ~= "" then
                local without_name, name = param:match("^(.*%S)%s+([%w_]+)$")
                if name and not code:find("%f[%w]" .. name .. "%f[%W]") then
                    kept[#kept + 1] = without_name -- drop the unused name, keep the type
                else
                    kept[#kept + 1] = param
                end
            end
        end
        return prefix .. table.concat(kept, ", ") .. suffix .. fn_body
    end

    return Cs((fn / rewrite + 1)^0):match(src)
end

local script_dir = debug.getinfo(1, "S").source:match("^@(.*/)") or "./"
local emulator_src_dir = script_dir .. "../../src/"
local solidity_src_dir = script_dir .. "../src/"

local function read_file(path)
    local f <close> = assert(io.open(path, "r"))
    return f:read("a")
end

function M.transpile(cpp_src, h_src, lib_name, entrypoint)
    local body = extract_namespace_body(cpp_src)
    body = strip_cpp_only(body)
    body = convert_fn_signatures(body, entrypoint)
    body = cpp_to_solidity_syntax(body)
    assert_solidity_dialect(body)

    -- Bridge function names live in uarch-solidity-compat.hpp on the emulator side.
    -- Match `static inline RETURN NAME(...)` to pick out the function names.
    local compat_src = read_file(emulator_src_dir .. "uarch-solidity-compat.hpp")
    local compat_fn_names = extract_names(
        compat_src,
        "static%s+inline%s+[%w_]+%s+([%w_]+)%s*%("
    )
    body = prefix_names(body, compat_fn_names, "StateAccess.")

    -- Constants live in solidity-step/src/EmulatorConstants.sol.
    local constants_names = extract_names(
        read_file(solidity_src_dir .. "EmulatorConstants.sol"),
        "constant%s+([%w_]+)"
    )
    body = prefix_names(body, constants_names, "EmulatorConstants.")

    body = blank_unused_param_names(body)

    -- Extract enums from the companion header (e.g. UArchStepStatus).
    local enums = ""
    if h_src then
        for ename, ebody in h_src:gmatch("enum class (%w+)%s*:%s*[%w_]+%s*{([^}]*)}") do
            enums = enums .. "    enum " .. ename .. " {" .. ebody .. "}\n"
        end
    end

    return M.LICENSE_BANNER .. "\n\n"
        .. "/// @dev This file is generated from C++ by solidity-step/tools/transpile-uarch.lua\n\n"
        .. "pragma solidity ^0.8.30;\n\n"
        .. "import {StepLog}           from \"src/StepLog.sol\";\n"
        .. "import {StateAccess}        from \"src/StateAccess.sol\";\n"
        .. "import {EmulatorConstants} from \"src/EmulatorConstants.sol\";\n\n"
        .. "library " .. lib_name .. " {\n"
        .. enums .. body .. "\n"
        .. "}\n"
end

local function help()
    io.stderr:write(string.format([=[
Usage:

  %s <input-cpp> <output-sol> <library-name> <entry-function>

Transpile a C++ uarch source file into a Solidity library.

Arguments:

  input-cpp       C++ source file to transpile (e.g. ../src/uarch-step.cpp).
                  If a companion .hpp or .h exists, enums are extracted from it.
  output-sol      Output .sol file path (e.g. src/UArchStep.sol)
  library-name    Solidity library name (e.g. UArchStep)
  entry-function  The library's public entry point (e.g. uarchStep).
                  Gets "internal" visibility; all others get "private".

]=], arg[0]))
    os.exit()
end

local function main()
    if not arg[1] or arg[1] == "-h" or arg[1] == "--help" then help() end
    local input_cpp      = arg[1]
    local output_sol     = assert(arg[2], "missing output-sol")
    local library_name   = assert(arg[3], "missing library-name")
    local entry_function = assert(arg[4], "missing entry-function")

    local input_cpp_src = read_file(input_cpp)
    local input_h_src
    for _, ext in ipairs({".hpp", ".h"}) do
        local h_path = input_cpp:gsub("%.cpp$", ext)
        local ok, src = pcall(read_file, h_path)
        if ok then input_h_src = src; break end
    end

    local result = M.transpile(input_cpp_src, input_h_src, library_name, entry_function)

    local f <close> = assert(io.open(output_sol, "w"))
    f:write(result)
    io.stderr:write("Generated " .. output_sol .. "\n")
end

if arg and arg[0] and arg[0]:match("/transpile%-uarch%.lua$") then
    main()
end

return M
