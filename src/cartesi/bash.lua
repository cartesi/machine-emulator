-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local _M = {}

-- The option name is a plain string; a trailing "=" marks a value-taking
-- option. Strip it to get the bare flag name.
local function flag_name(name) return (name:gsub("=$", "")) end

local function name_takes_value(name) return name:sub(-1) == "=" end

-- Sentinels for subkey value kinds that bash completes specially.
local SUBKEY_KIND_SENTINEL = {
    file = "__file__",
    dir = "__dir__",
    number = "__number__",
    string = "__string__",
    hostport = "__string__",
    netif = "__string__",
}

-- Reduce one options-table entry to a completion descriptor.
local function describe_option(entry)
    local name, hint = entry[1], entry[3]
    local flag = flag_name(name)
    if flag == "" or not flag:match("^%-") then return nil end
    local has_value = name_takes_value(name)
    -- A plain name cannot encode an optional value; optional-value options are
    -- two entries (flag + value) merged below, which sets optional there.
    local desc = {
        flag = flag,
        kind = has_value and "string" or "bare",
        optional = false,
    }
    if type(hint) == "string" then
        if hint:sub(-1) == "?" then
            desc.kind = hint:sub(1, -2)
            desc.optional = true
        else
            desc.kind = hint
        end
    elseif type(hint) == "table" then
        desc.kind = "compound"
        desc.subkeys = {}
        desc.subkey_values = {}
        -- The array part (hint[1]) names the positional sub-key. Record either
        -- its enum values or its kind so a bare value can be completed.
        if hint[1] then
            local positional = hint[hint[1]]
            if type(positional) == "table" then
                desc.positional_values = {}
                for value in pairs(positional) do
                    desc.positional_values[#desc.positional_values + 1] = value
                end
                table.sort(desc.positional_values)
            else
                desc.positional_kind = positional
            end
        end
        for k, v in pairs(hint) do
            -- skip the array part (the positional sub-key name, handled above)
            if type(k) == "string" then
                desc.subkeys[#desc.subkeys + 1] = k
                if type(v) == "table" then
                    local vals = {}
                    for ek in pairs(v) do
                        vals[#vals + 1] = ek
                    end
                    table.sort(vals)
                    desc.subkey_values[k] = vals
                elseif v == "boolean" then
                    desc.subkey_values[k] = { "true", "false" }
                else
                    desc.subkey_values[k] = SUBKEY_KIND_SENTINEL[v] or "__string__"
                end
            end
        end
        table.sort(desc.subkeys)
    end
    return desc
end

local function bash_quote(s) return "'" .. (s:gsub("'", "'\\''")) .. "'" end

local bash_completion_function = [==[
_cartesi_complete() {
    local cur="${COMP_WORDS[$COMP_CWORD]}"
    local line="${COMP_LINE:0:$COMP_POINT}"
    local logical="${line##*[[:space:]]}"
    COMPREPLY=()

    if [[ "$logical" != -* ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
    fi

    if [[ "$logical" != *=* ]]; then
        local f k
        for f in "${!_cm_flag_kind[@]}"; do
            if [[ "$f" == "$logical"* ]]; then
                k="${_cm_flag_kind[$f]}"
                if [[ "$k" == "bare" ]]; then
                    # Trailing space so cursor moves on. compopt -o nospace
                    # below suppresses bash's auto-space, so we add it ourselves.
                    COMPREPLY+=("$f ")
                else
                    COMPREPLY+=("$f=")
                    [[ -n "${_cm_flag_optional[$f]:-}" ]] && COMPREPLY+=("$f ")
                fi
            fi
        done
        compopt -o nospace 2>/dev/null
        return
    fi

    local flag="${logical%%=*}"
    local rest="${logical#*=}"
    local kind="${_cm_flag_kind[$flag]:-}"

    local cur_partial="$cur"
    while [[ "$cur_partial" == [=:]* ]]; do
        cur_partial="${cur_partial:1}"
    done

    case "$kind" in
        file) COMPREPLY=( $(compgen -f -- "$cur_partial") ); compopt -o nospace 2>/dev/null ;;
        dir)  COMPREPLY=( $(compgen -d -- "$cur_partial") ); compopt -o nospace 2>/dev/null ;;
        number|hostport|netif|string) ;;
        compound)
            local last_segment="${rest##*,}"
            if [[ "$last_segment" == *:* ]]; then
                local subkey="${last_segment%%:*}"
                local val_prefix="${last_segment#*:}"
                local values="${_cm_subkey_values[${flag},${subkey}]:-}"
                case "$values" in
                    __file__) COMPREPLY=( $(compgen -f -- "$val_prefix") ); compopt -o nospace 2>/dev/null ;;
                    __dir__)  COMPREPLY=( $(compgen -d -- "$val_prefix") ); compopt -o nospace 2>/dev/null ;;
                    __number__|__string__|"") ;;
                    *)        COMPREPLY=( $(compgen -W "$values" -- "$val_prefix") ) ;;
                esac
            else
                local subkeys="${_cm_compound_keys[$flag]:-}"
                local partial="$last_segment"
                local prefix="${cur_partial%$partial}"
                local matched=( $(compgen -W "$subkeys" -- "$partial") )
                local i
                for i in "${!matched[@]}"; do
                    matched[$i]="${prefix}${matched[$i]}:"
                done
                COMPREPLY=("${matched[@]}")
                # a bare value (no subkey:) may be the positional; offer files/dirs
                case "${_cm_positional_kind[$flag]:-}" in
                    file) COMPREPLY+=( $(compgen -f -- "$partial") ) ;;
                    dir)  COMPREPLY+=( $(compgen -d -- "$partial") ) ;;
                esac
                local positional_values="${_cm_positional_values[$flag]:-}"
                [[ -n "$positional_values" ]] && COMPREPLY+=( $(compgen -W "$positional_values" -- "$partial") )
                compopt -o nospace 2>/dev/null
            fi
            ;;
    esac
}
]==]

-- Walk an options table and emit a self-contained bash completion script
-- registering the given program names. Writes to io.stdout.
function _M.dump_bash_completion(options, program_names)
    local flags = {}
    local ordered = {}
    for _, entry in ipairs(options) do
        local d = describe_option(entry)
        if d then
            local prev = flags[d.flag]
            if prev then
                if prev.kind == "bare" and d.kind ~= "bare" then
                    prev.kind, prev.subkeys, prev.subkey_values = d.kind, d.subkeys, d.subkey_values
                    prev.positional_kind = d.positional_kind
                    prev.positional_values = d.positional_values
                    prev.optional = true
                elseif d.kind == "bare" and prev.kind ~= "bare" then
                    prev.optional = true
                else
                    prev.optional = prev.optional or d.optional
                end
            else
                flags[d.flag] = d
                ordered[#ordered + 1] = d.flag
            end
        end
    end
    table.sort(ordered)

    local w = function(s) io.write(s, "\n") end

    w("# bash completion for " .. table.concat(program_names, ", "))
    w("# Generated by cartesi.bash.dump_bash_completion. Do not edit by hand.")
    w("declare -gA _cm_flag_kind=()")
    w("declare -gA _cm_flag_optional=()")
    w("declare -gA _cm_compound_keys=()")
    w("declare -gA _cm_subkey_values=()")
    w("declare -gA _cm_positional_kind=()")
    w("declare -gA _cm_positional_values=()")
    for _, flag in ipairs(ordered) do
        local d = flags[flag]
        w(string.format("_cm_flag_kind[%s]=%s", bash_quote(flag), bash_quote(d.kind)))
        if d.optional then w(string.format("_cm_flag_optional[%s]=1", bash_quote(flag))) end
        if d.positional_kind then
            w(string.format("_cm_positional_kind[%s]=%s", bash_quote(flag), bash_quote(d.positional_kind)))
        end
        if d.positional_values then
            w(
                string.format(
                    "_cm_positional_values[%s]=%s",
                    bash_quote(flag),
                    bash_quote(table.concat(d.positional_values, " "))
                )
            )
        end
        if d.subkeys then
            w(string.format("_cm_compound_keys[%s]=%s", bash_quote(flag), bash_quote(table.concat(d.subkeys, " "))))
            for _, k in ipairs(d.subkeys) do
                local v = d.subkey_values[k]
                local val_str = type(v) == "table" and table.concat(v, " ") or v
                w(string.format("_cm_subkey_values[%s,%s]=%s", bash_quote(flag), bash_quote(k), bash_quote(val_str)))
            end
        end
    end
    w(bash_completion_function)
    w("complete -F _cartesi_complete " .. table.concat(program_names, " "))
end

return _M
