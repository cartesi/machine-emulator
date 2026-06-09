-- Pandoc Lua filter for the inline-script docs build system.
--
-- PURPOSE
--
-- Turns README.md.template into README.md. Code blocks annotated with key=
-- are written to cache/<key>/, executed by `make`, and their outputs spliced
-- back into the rendered document. The driving Makefile lives in
-- recipes/Makefile; it calls this filter twice with `make` in between.
--
-- LIFECYCLE (three invocations)
--
--   1. Dry-run: pass -M write-user-dependencies=<target> to pandoc and use
--      pandoc's normal -o <path> for the output. The filter walks the
--      template, writes each block body to cache/<key>/body.<ext>
--      (idempotently), writes cache/<key>/spec when contents-form vars=
--      entries exist, builds a self-contained makefile fragment with <target>
--      on the LHS of the prereqs line, and replaces the document body with a
--      single RawBlock containing that text. With -t plain, pandoc emits the
--      RawBlock verbatim, so <path> ends up holding the makefile fragment.
--      Cached outputs are not read in this pass and replace=K/both and similar
--      return "".
--
--   2. The Makefile includes the .d file. <target>'s prereq line lists every
--      cache file the document needs. Each rule says "to produce
--      cache/<key>/both, depend on the runner, cache/<key>/body.<ext>, and
--      each dep's output file, then exec the runner". Running `make` executes
--      every needed body in topological order, populating the cache.
--
--   3. Real run: same filter, same template, -M write-user-dependencies absent.
--      Every cache/<key>/<sub> the document needs now exists on disk. The
--      filter reads those files and splices their contents in place of the
--      annotated blocks. Pandoc's output is the final rendered document.
--
-- TWO-PASS WALK (each invocation)
--
--   Pass 1 (collect): pandoc.walk_block records every key= block body, parsed
--   deps, and parsed vars into `pending` without resolving anything.
--   Detects duplicate keys.
--
--   Pass 2 (render): walk in document order. When a replace=K/... is seen,
--   ensure_defined(K) lazily defines K -- recursing depth-first through K's
--   depends= and vars= chains -- before reading its output. This is what
--   makes replace= and depends= order-independent within the document.
--
-- REQUIRED ENVIRONMENT
--
--   REPLACE_CACHE_DIR  Absolute path to the cache directory (errors if unset).
--   REPLACE_DIR Derived from PANDOC_SCRIPT_FILE; runners and vars.lua
--              live alongside this filter file.
--
-- CACHE LAYOUT
--
--   cache/<key>/body.<ext>     Source written at dry-run time (idempotent).
--   cache/<key>/spec           VAR=path lines for contents-form vars= entries
--                              (written at dry-run time, idempotent).
--   cache/<key>/outputs        Declared artifact filenames, one per line
--                              (written at dry-run time, idempotent; empty
--                              when outputs= is absent). Read by the runner
--                              after the body exits to verify each artifact
--                              exists.
--   cache/<key>/body.run.<ext> Body with contents-form $VAR expanded (runner-produced).
--   cache/<key>/stdout         Captured standard output (runner-produced).
--   cache/<key>/stderr         Captured standard error (runner-produced).
--   cache/<key>/both           stdout and stderr interleaved (runner-produced;
--                              primary make target -- the others are siblings).
--                              For include= keys this file is written at filter
--                              time and holds the published body; no other
--                              cache/<key>/ files are produced.
--   cache/<key>/<artifact>     Any declared outputs= artifact. The runner cd's
--                              into cache/<key>/ before running the body, so
--                              artifacts written to cwd land there automatically.
--
-- CACHE INVALIDATION
--
--   Make drives invalidation via mtimes. body.<ext> and spec are written
--   idempotently (skipped when content is unchanged) to avoid spurious rebuilds.
--   The runner (run-bash.sh / run-lua.sh) and vars.lua are listed as make
--   prereqs for every rule that uses them, so editing those files triggers
--   a rebuild of all affected blocks.
--
-- LANGUAGES
--
--   LANG_INFO maps a Pandoc class name to {ext, runner-path}:
--     .bash  ->  body.sh,  run-bash.sh   (default)
--     .lua   ->  body.lua, run-lua.sh
--   pick_lang uses runner= when set, else the first Pandoc class, else
--   DEFAULT_LANG (bash). The class always controls syntax highlighting.
--   To add a language: add an entry to LANG_INFO and place run-<lang>.sh
--   alongside this filter.
--
-- ATTRIBUTES (CodeBlock / Code / Span)
--
--   key=K               Defines block K. Body is its source.
--                       K must match [a-zA-Z_][a-zA-Z0-9_]*; duplicates error.
--                       $REPLACE_KEY is replaced with K before writing body.
--
--   depends=A,B,...     Only on key= blocks. Each token is either bare K or
--                       K/SUB. Bare K adds a make prereq on cache/<K>/both;
--                       K/SUB pins cache/<K>/SUB (stream or declared artifact).
--                       Reserved for ordering-only cases. Use vars= when $K
--                       is in the body. For chains of blocks that share a
--                       runtime resource (e.g., a TCP port), prefer
--                       sequential= so the chain is built automatically in
--                       document order.
--
--   sequential=TAG      Only on key= blocks. TAG is a single identifier.
--                       Every block with the same TAG is auto-chained in
--                       document order: each non-first member gains an
--                       implicit depends=<previous-member>, a make prereq on
--                       cache/<previous-member>/both. Composes additively
--                       with explicit depends= and vars=. Use for ordering-
--                       only resources (a bound port, a fixed file path)
--                       where listing the chain by hand would be brittle.
--                       Not allowed on include= keys (those have no
--                       executable body to serialize).
--
--   vars=VAR->REF,...  Path injection and contents substitution. REF forms:
--                         VAR->K          contents-form: $VAR -> bytes of cache/<K>/both
--                                         (same default as replace=K)
--                         VAR->K/SUB      contents-form: $VAR -> bytes of cache/<K>/SUB
--                         VAR->K/SUB/path path-form: $VAR -> REPLACE_CACHE_DIR/K/SUB
--                         K               path-form: $K -> K/path (shortcut)
--                       Path-form entries are substituted in body.<ext> at dry-run
--                       time. Contents-form entries are written to cache/<K>/spec
--                       and expanded by vars.lua at runner time (producing
--                       body.run.<ext>). Both forms also add make prereqs.
--
--   runner=<name>       Optional, key= blocks only. Overrides the runner (and body
--                       file extension) that replace.lua would otherwise infer from
--                       the block's Pandoc class. <name> must match a key in
--                       LANG_INFO; if it does not, the block is display-only (no
--                       body file written, no runner invocation). Consuming the
--                       captured output (replace=K/stdout etc.) of a display-only
--                       block is an error. Has no effect on include= keys (which
--                       never execute and produce only cache/<K>/both).
--                       Not allowed on inline Code or Span.
--
--   outputs=a,b,c       Only on key= blocks. Declares artifact filenames the body
--                       writes to its cwd (= cache/<key>/). Reserved names
--                       (stdout, stderr, both, source, null) are rejected.
--                       The runner verifies each artifact exists after the body
--                       exits and fails if it does not.
--
--   include=<path>      Only on key= blocks. The block's body is the body of
--                       the included thing: the contents of $RECIPES_DIR/<path>
--                       with docs:begin/docs:end markers stripped (infrastructure
--                       markers, not content). Block body must be empty when
--                       include= is set. outputs=, depends=, and vars= are not
--                       allowed on include= keys. The filter writes the body to
--                       cache/<K>/both at filter time; the make rule touches that
--                       file when the included file changes so consumers
--                       invalidate. No stdout, stderr, or body.<ext> are produced
--                       (an include= block does not execute -- it just publishes
--                       its body). replace= defaults to "both" on include= blocks;
--                       only replace=both and replace=null are accepted.
--                       Region-selecting form: include=<file>/<region>. The
--                       whole value is tried as a file path first. If that
--                       fails, the value is split on the last '/' into <file>
--                       and <region>: only the lines within the named
--                       docs:begin/docs:end region of <file> become the body
--                       (markers stripped).
--
--   enabled=yes|no      Optional. Controls whether this block is active.
--                       When absent, the value of the -M default-replace=
--                       pandoc variable applies (true/yes/1 -> enabled;
--                       false/no/0 or missing -> disabled). When disabled,
--                       the block's entire body is rendered verbatim as a
--                       plain code block (no execution, no region trimming,
--                       no docs:begin/end processing). Cross-block
--                       replace= sites that reference a disabled key
--                       render as empty. ensure_defined errors if an
--                       enabled block depends on a disabled one.
--
--   code=yes|no         Optional, inline Span only. Default yes wraps the
--                       substituted value in an inline Code element (matches
--                       backtick styling). Set code=no to emit plain text,
--                       useful inside HTML markup like <sup>...</sup> where
--                       monospace styling looks wrong.
--
--   replace=<value>     Required on every annotated block except include= blocks,
--                       where it defaults to "both". See taxonomy below.
--
-- REPLACE= TAXONOMY
--
--   null                Drop the block from output. Body still runs when key=
--                       is present. Idiom: hidden setup block.
--
--   source              Render this key's body. Requires key=.
--   source/<region>     Render only the named docs:begin/end region. Requires key=.
--                       "null" is reserved and cannot be used as a region name.
--
--   stdout|stderr|both  Render this key's captured stream. Requires key=.
--
--   <artifact>          Render this key's declared artifact. Requires key=;
--                       artifact name must appear in outputs=.
--
--   K                   Cross-block: render K's "both" output (default thing).
--   K/path              Cross-block: absolute path of cache/<K>/ directory.
--   K/<thing>           Cross-block: render K's thing.
--                       thing is stdout|stderr|both|source[/<region>]|<artifact>.
--                       When K was defined with include=, only the bare K,
--                       K/both, K/path, and K/both/path forms are accepted.
--   K/<thing>/path      Cross-block: absolute path of cache/<K>/<thing>.
--                       Forces lazy definition of K via ensure_defined.
--
--   Inline Code:        Only cross-block forms (K or K/<thing>) are allowed.
--   Inline Span:        Only cross-block forms. The Span's inline content is
--                       appended as a literal suffix to the rendered output
--                       (idiom: insert punctuation after a substituted value).
--                       Wrapped in inline Code by default; pass code=no to
--                       emit plain text instead.
--
-- DOCS:BEGIN/END SEMANTICS
--
--   Marker syntax:  <comment-leader> docs:begin <name>
--                   <comment-leader> docs:end   <name>
--   Comment leaders: #, --, // (with optional surrounding whitespace).
--   <name> may be empty (unnamed default region).
--
--   Special name "null":
--     docs:begin null / docs:end null lines and everything between them are
--     stripped from the rendered source but still execute. Use this to hide
--     imports or setup boilerplate. Multiple non-overlapping null regions are
--     allowed; nesting is not permitted. The marker lines themselves are
--     also stripped from the executed body, so a null region may be inserted
--     in the middle of a bash backslash-continued multi-line command without
--     bash gluing the leading "#" onto the previous "\<NL>" continuation.
--
--   Named region:
--     replace=source/<name> renders only the content between the matching
--     docs:begin <name> / docs:end <name> pair. Markers are stripped.
--
-- OUTPUT POST-PROCESSING
--
--   read_output strips ANSI escape sequences and the trailing newline before
--   substitution. Bodies relying on exact byte-level capture should not use
--   replace= to consume their output.
--
-- GLOBALS PSEUDO-KEY
--
--   Pandoc() writes every pandoc metadata variable whose name starts with a
--   letter or underscore (hyphens are also allowed after the first character)
--   to REPLACE_CACHE_DIR/globals/<name>. Pass the value on the pandoc command
--   line with -M NAME=VALUE. Use vars=VAR->globals/NAME (contents-form) to
--   inject the value into a block body or a replace=source display, or
--   replace=globals/NAME to render the value as the block's content
--   (replace=globals/NAME/path yields the absolute path of the file).
--
-- DEFAULT-REPLACE METADATA
--
--   Pass -M default-replace=true (or false) on the pandoc command line.
--   replace.lua reads doc.meta["default-replace"] in Pandoc() and uses it
--   as the default for blocks without an explicit enabled= attribute.
--   true/yes/1 -> enabled; false/no/0 (or absent) -> disabled.
--
-- MAKE-FRAGMENT SHAPE (dry-run)
--
--   Grouped target: cache/<key>/both, cache/<key>/stdout, cache/<key>/stderr,
--     and each declared artifact, emitted as one GNU Make grouped target
--     (`&:`, requires GNU Make >= 4.3; template.d is only -included inside the
--     docs container). One runner invocation co-produces all of them, so the
--     grouped form lets make invalidate every consumer whenever a prereq
--     changes. The older `sibling: primary` empty-recipe form could leave an
--     indirect consumer (e.g. one reading another block's reordered stdout)
--     stale on a timestamp tie across the two-pass rebuild.
--     prereqs: runner, body.<ext>, outputs, [vars.lua, spec] (iff contents-form
--              vars= exists), depends= prereqs, vars= file prereqs
--
--   include= keys take a simpler shape: a single rule whose only prereq is
--   the included file, with recipe `touch cache/<key>/both`. The content is
--   written by the filter; the touch only propagates mtime so consumers
--   invalidate when the included file changes.
--
-- PANDOC RENDERING QUIRK
--
--   force_fenced upgrades classless CodeBlocks to class "text" so Pandoc
--   emits a fenced (not 4-space-indented) GFM code block.
--
-- INVARIANTS / GOTCHAS
--
--   - Duplicate key= definitions error during pass 1.
--   - Dependency cycles error during ensure_defined.
--   - outputs= artifacts not written by the body cause the runner to fail.
--   - vars= path-form rewrites happen at dry-run time (before execution).
--     Contents-form $VAR stays literal in body.<ext>; vars.lua expands it
--     at runner time. Editing vars.lua or the spec file triggers a rebuild.
--   - $VAR substitution requires a non-word boundary after VAR so $foo does
--     not consume the start of $foobar; longest var wins for disambiguation.
--   - include= keys publish only cache/<K>/both (the body). The filter writes
--     it at filter time via write_idempotent; the make rule has the included
--     file as its sole prereq and touches the primary, forcing consumers to
--     invalidate when the source changes (pass 3 rewrites the body during the
--     README.md build). Cross-block references to an include= key may only use
--     K, K/both, K/path, or K/both/path -- /source, /stdout, /stderr, and
--     artifact subs are rejected.

local deps_target
local default_enabled = true -- overridden in Pandoc() from -M default-replace=
local REPLACE_CACHE_DIR = os.getenv("REPLACE_CACHE_DIR") or error("REPLACE_CACHE_DIR not set")
local RECIPES_DIR = os.getenv("RECIPES_DIR") or error("RECIPES_DIR not set")

-- Locate the directory containing this filter file; runners live alongside it.
local REPLACE_DIR = PANDOC_SCRIPT_FILE:match("(.+)/[^/]+$") or "."
local vars = require("vars")

local LANG_INFO = {
    bash = { ext = "sh", runner = REPLACE_DIR .. "/run-bash.sh" },
    lua = { ext = "lua", runner = REPLACE_DIR .. "/run-lua.sh" },
}
local DEFAULT_LANG = "bash"

local RESERVED = { stdout = true, stderr = true, both = true, source = true, null = true }

-- State accumulated as the document is walked.
local pending = {} -- key -> { attr, body, classes, deps, vars }  (pass 1: raw collection)
local defining = {} -- key -> true  (cycle detection during ensure_defined)
local defined = {} -- key -> true  (set after define_script completes)
local outputs_t = {} -- key -> { artifact_name -> true }
local sources = {} -- key -> resolved body (for replace=source)
local rules = {} -- list of make rule strings (dry-run only)
local consumed = {} -- "<key>/<file>" -> true (referenced cache files)
local no_runner = {} -- key -> lang string (for keys whose runner= is not in LANG_INFO)
local sequential = {} -- tag -> last-seen key with this sequential= tag (built during collect)

-- Defined further below, but referenced by define_script above their definition.
local emit_rule, emit_include_rule

local function assertf(cond, fmt, ...)
    if not cond then
        error(string.format(fmt, ...))
    end
end

local function check_identifier(s, label)
    assertf(s:match("^[%a_][%w_]*$"), "%s: '%s' is not an identifier (must match [a-zA-Z_][a-zA-Z0-9_]*)", label, s)
end

local function strip_ansi(s)
    return (s:gsub("\27%[[%d;]*[mGK]", ""):gsub("\r", ""))
end

local function is_enabled(attr)
    local v = attr.enabled
    if v == nil then
        return default_enabled
    end
    return v == "yes" or v == "true" or v == "1"
end

local function parse_list(s)
    local r = {}
    if not s then
        return r
    end
    for tok in s:gmatch("[^,%s]+") do
        r[#r + 1] = tok
    end
    return r
end

local function parse_depends(s)
    local r = {}
    for _, tok in ipairs(parse_list(s)) do
        local base, sub = tok:match("^([%w_][%w_%-%.]*)/(.+)$")
        if not base then
            base = tok
        end
        check_identifier(base, "depends=" .. tok)
        r[#r + 1] = { base = base, sub = sub }
    end
    return r
end

local function parse_sequential(s)
    if not s then
        return nil
    end
    local tag = s:match("^%s*(.-)%s*$")
    assertf(tag ~= "", "sequential=%s: empty tag", s)
    assertf(not tag:find("[,%s]"), "sequential=%s: only one tag per block (no commas or whitespace)", s)
    check_identifier(tag, "sequential=" .. tag)
    return tag
end

local function parse_vars(s)
    local r = {}
    if not s then
        return r
    end
    for tok in s:gmatch("[^,%s]+") do
        local var, ref = tok:match("^([%w_]+)%->(.+)$")
        local shortcut = var == nil
        if shortcut then
            check_identifier(tok, "vars=" .. tok)
            var, ref = tok, tok
        end
        assertf(ref:match("^[%w._%-/]+$"), "vars=%s->%s: invalid characters in ref", var, ref)
        local base, sub, kind
        -- Try K/SUB/path
        base, sub = ref:match("^([%w_][%w_%-%.]*)/(.+)/path$")
        if base then
            assertf(not sub:match("^source/"), "vars=%s->%s: K/source/REGION/path is not allowed", var, ref)
            kind = "path"
        else
            -- Try K/SUB
            base, sub = ref:match("^([%w_][%w_%-%.]*)/(.+)$")
            if base then
                kind = "contents"
            elseif shortcut then
                base, sub = ref, nil
                kind = "dirpath"
            else
                -- vars=VAR->K defaults to vars=VAR->K/both (contents-form).
                base, sub = ref, "both"
                kind = "contents"
            end
        end
        check_identifier(base, "vars=" .. var .. "->" .. ref)
        r[#r + 1] = { var = var, base = base, sub = sub, kind = kind, raw = ref }
    end
    return r
end

-- Substitute $VAR in body with abs_path for each {var, abs_path} pair.
-- Longest var wins; match requires a non-word character (or end) after the var
-- so $foo does not consume the start of $foobar.
local function substitute(body, var_pairs)
    local sorted_pairs = {}
    for _, p in ipairs(var_pairs) do
        sorted_pairs[#sorted_pairs + 1] = p
    end
    table.sort(sorted_pairs, function(a, b)
        return #a.var > #b.var
    end)
    local out, i, n = {}, 1, #body
    while i <= n do
        local c = body:sub(i, i)
        if c == "$" then
            local matched = false
            for _, p in ipairs(sorted_pairs) do
                local len = #p.var
                if body:sub(i + 1, i + len) == p.var then
                    local nextc = body:sub(i + 1 + len, i + 1 + len)
                    if nextc == "" or not nextc:match("[%w._%-]") then
                        out[#out + 1] = p.abs_path
                        i = i + 1 + len
                        matched = true
                        break
                    end
                end
            end
            if not matched then
                out[#out + 1] = "$"
                i = i + 1
            end
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    return table.concat(out)
end

-- Process docs:begin null / docs:end null pairs. When keep_content is false
-- (the rendered-source path), the markers and the lines between them are
-- removed. When keep_content is true (the executed-body path), only the
-- marker lines themselves are removed; the lines between them survive. The
-- latter mode lets a null region sit in the middle of a bash backslash-
-- continued command without bash collapsing "\<NL>" + "# docs:begin null"
-- into a comment that severs the logical line.
-- Multiple non-overlapping null regions are allowed. Nesting is not.
local function process_null_regions(body, keep_content, label)
    if not body:find("[#%-/]+%s*docs:begin%s+null") then
        return body
    end
    local scan = body:sub(-1) == "\n" and body or (body .. "\n")
    local out = {}
    local in_null = false
    for line in scan:gmatch("([^\n]*)\n") do
        if line:match("^%s*[#%-/]+%s*docs:begin%s+null%s*$") then
            assertf(not in_null, "%s: nested docs:begin null", label)
            in_null = true
        elseif line:match("^%s*[#%-/]+%s*docs:end%s+null%s*$") then
            assertf(in_null, "%s: docs:end null without matching docs:begin null", label)
            in_null = false
        elseif keep_content or not in_null then
            out[#out + 1] = line
        end
    end
    assertf(not in_null, "%s: unterminated docs:begin null", label)
    local result = table.concat(out, "\n")
    if body:sub(-1) == "\n" then
        result = result .. "\n"
    end
    return result
end

local function strip_null_regions(body, label)
    return process_null_regions(body, false, label)
end

local function strip_null_markers(body, label)
    return process_null_regions(body, true, label)
end

-- Strip every docs:begin / docs:end marker line from body.
-- Used for include= keys so infrastructure markers do not appear in output.
local function strip_all_markers(body)
    local scan = body:sub(-1) == "\n" and body or (body .. "\n")
    local out = {}
    for line in scan:gmatch("([^\n]*)\n") do
        if not line:match("^%s*[#%-/]+%s*docs:%a+") then
            out[#out + 1] = line
        end
    end
    local result = table.concat(out, "\n")
    if body:sub(-1) == "\n" then
        result = result .. "\n"
    end
    return result
end

-- Extract a "docs:begin NAME" / "docs:end NAME" region from body.
-- Comment leaders #, --, // (and variants) are stripped before the keyword.
-- NAME may be empty (the unnamed default region). Markers are stripped.
local function extract_region(body, name, label)
    local target = name or ""
    local markers = {}
    -- Ensure the last line is terminated so a final docs:end at EOF is matched.
    local scan = body:sub(-1) == "\n" and body or (body .. "\n")
    scan:gsub("()[%s]*[#%-/]+[%s]*docs:(%a+)[ \t]*(.-)[ \t]*()\n", function(s, kw, rname, e)
        markers[#markers + 1] = { s = s, kw = kw, name = rname, e = e }
    end)
    local regions = {}
    for _, m in ipairs(markers) do
        regions[m.name] = regions[m.name] or {}
        local r = regions[m.name]
        if m.kw == "begin" then
            assertf(not r.first, "%s: duplicate docs:begin '%s'", label, m.name)
            r.first = m.e + 1
        elseif m.kw == "end" then
            assertf(not r.last, "%s: duplicate docs:end '%s'", label, m.name)
            r.last = m.s - 1
        end
    end
    local r = regions[target]
    assertf(r, "%s: no region '%s' found", label, target)
    assertf(r.first, "%s: region '%s' has no docs:begin", label, target)
    assertf(r.last, "%s: region '%s' has no docs:end", label, target)
    assertf(r.first <= r.last, "%s: region '%s' docs:end before docs:begin", label, target)
    return (scan:sub(r.first, r.last):gsub("\n$", ""))
end

local function read_file(path, label)
    local f = io.open(path, "r")
    assertf(f, "%s: cannot open %s", label, path)
    local txt = f:read("a")
    f:close()
    return txt
end

local function read_output(key, sub, label)
    assertf(
        not no_runner[key],
        "%s: runner=%s is not in LANG_INFO; cannot consume cache/%s/%s",
        label,
        no_runner[key],
        key,
        sub
    )
    consumed[key .. "/" .. sub] = true
    if deps_target then
        return ""
    end
    local path = REPLACE_CACHE_DIR .. "/" .. key .. "/" .. sub
    return (strip_ansi(read_file(path, label)):gsub("\n$", ""))
end

local function pick_lang(attr, classes)
    return attr.runner or classes and classes[1] or DEFAULT_LANG
end

local function write_idempotent(path, content)
    local f = io.open(path, "r")
    if f then
        local existing = f:read("a")
        f:close()
        if existing == content then
            return
        end
    end
    os.execute("mkdir -p '" .. path:match("(.*)/") .. "'")
    f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
end

local function define_script(key, attr, body, classes, deps, vars_list, include_abs)
    assertf(not defined[key], "key=%s: duplicate definition", key)
    local out_list = parse_list(attr.outputs)
    for _, n in ipairs(out_list) do
        assertf(not RESERVED[n], "key=%s: outputs= cannot contain reserved name '%s'", key, n)
    end
    if include_abs then
        assertf(#out_list == 0, "key=%s: outputs= not allowed on include= keys", key)
        assertf(#deps == 0, "key=%s: depends= not allowed on include= keys", key)
        assertf(#vars_list == 0, "key=%s: vars= not allowed on include= keys", key)
        defined[key] = true
        outputs_t[key] = {}
        write_idempotent(REPLACE_CACHE_DIR .. "/" .. key .. "/both", body)
        if deps_target then
            emit_include_rule(key, include_abs)
        end
        return
    end
    for _, d in ipairs(deps) do
        assertf(defined[d.base], "key=%s: depends=%s: '%s' not yet defined", key, d.base, d.base)
    end
    -- Build path_pairs from path-form vars entries (kind == "dirpath" or "path").
    -- Contents-form entries stay literal in the body; the runner will expand them at run time.
    local path_pairs = {}
    for _, p in ipairs(vars_list) do
        if p.kind == "dirpath" then
            assertf(defined[p.base], "key=%s: vars=%s->%s: '%s' not yet defined", key, p.var, p.raw, p.base)
            path_pairs[#path_pairs + 1] = { var = p.var, abs_path = REPLACE_CACHE_DIR .. "/" .. p.base }
        elseif p.kind == "path" then
            assertf(defined[p.base], "key=%s: vars=%s->%s: '%s' not yet defined", key, p.var, p.raw, p.base)
            path_pairs[#path_pairs + 1] = { var = p.var, abs_path = REPLACE_CACHE_DIR .. "/" .. p.base .. "/" .. p.sub }
        end
    end
    local resolved = substitute(body, path_pairs)
    resolved = resolved:gsub("%$REPLACE_KEY%f[%W]", function()
        return key
    end)
    local lang = pick_lang(attr, classes)
    local info = LANG_INFO[lang]
    defined[key] = true
    outputs_t[key] = {}
    for _, n in ipairs(out_list) do
        outputs_t[key][n] = true
    end
    sources[key] = resolved
    if not info then
        no_runner[key] = lang
        return resolved
    end
    local exec_body = strip_null_markers(resolved, "key=" .. key)
    write_idempotent(REPLACE_CACHE_DIR .. "/" .. key .. "/body." .. info.ext, exec_body)
    -- Write spec file for contents-form vars entries so the runner can expand them.
    local contents_entries = {}
    for _, p in ipairs(vars_list) do
        if p.kind == "contents" then
            contents_entries[#contents_entries + 1] = p
        end
    end
    if #contents_entries > 0 then
        table.sort(contents_entries, function(a, b)
            return a.var < b.var
        end)
        local lines = {}
        for _, p in ipairs(contents_entries) do
            lines[#lines + 1] = p.var .. "=" .. REPLACE_CACHE_DIR .. "/" .. p.base .. "/" .. p.sub
        end
        write_idempotent(REPLACE_CACHE_DIR .. "/" .. key .. "/spec", table.concat(lines, "\n") .. "\n")
    end
    -- Always write the outputs file (consumed by the runner to verify declared
    -- artifacts exist after the body completes). Written even when empty so a
    -- removed outputs= attribute clears any stale list.
    local outputs_text = ""
    if #out_list > 0 then
        local sorted_out = {}
        for _, n in ipairs(out_list) do
            sorted_out[#sorted_out + 1] = n
        end
        table.sort(sorted_out)
        outputs_text = table.concat(sorted_out, "\n") .. "\n"
    end
    write_idempotent(REPLACE_CACHE_DIR .. "/" .. key .. "/outputs", outputs_text)
    if deps_target then
        emit_rule(key, info, out_list, deps, vars_list, #contents_entries > 0)
    end
    return resolved
end

-- Emit a make rule. One runner invocation produces both, stdout, stderr, and
-- any declared artifacts together, so they are emitted as a single GNU Make
-- grouped target (`&:`, requires GNU Make >= 4.3, satisfied by the docs image;
-- template.d is only -included inside the container). The grouped form tells
-- make the recipe co-produces every output, so editing an intermediate block
-- reliably invalidates its consumers. The previous `sibling: primary` form left
-- consumers stale when timestamps tied across the two-pass rebuild.
function emit_rule(key, info, out_list, deps, vars_list, has_contents)
    local runner_path = info.runner
    local body_path = "$(REPLACE_CACHE_DIR)/" .. key .. "/body." .. info.ext
    local prereqs = { runner_path, body_path, "$(REPLACE_CACHE_DIR)/" .. key .. "/outputs" }
    if has_contents then
        prereqs[#prereqs + 1] = REPLACE_DIR .. "/vars.lua"
        prereqs[#prereqs + 1] = "$(REPLACE_CACHE_DIR)/" .. key .. "/spec"
    end
    -- Collect prereqs from depends= and vars=, deduplicating by path.
    local seen_prereqs = {}
    local function add_prereq(path)
        if not seen_prereqs[path] then
            seen_prereqs[path] = true
            prereqs[#prereqs + 1] = path
        end
    end
    for _, d in ipairs(deps) do
        add_prereq("$(REPLACE_CACHE_DIR)/" .. d.base .. "/" .. (d.sub or "both"))
    end
    for _, p in ipairs(vars_list) do
        if p.kind == "dirpath" then
            add_prereq("$(REPLACE_CACHE_DIR)/" .. p.base .. "/both")
        elseif p.kind == "path" or p.kind == "contents" then
            add_prereq("$(REPLACE_CACHE_DIR)/" .. p.base .. "/" .. p.sub)
        end
    end
    local targets = {
        "$(REPLACE_CACHE_DIR)/" .. key .. "/both",
        "$(REPLACE_CACHE_DIR)/" .. key .. "/stdout",
        "$(REPLACE_CACHE_DIR)/" .. key .. "/stderr",
    }
    for _, n in ipairs(out_list) do
        targets[#targets + 1] = "$(REPLACE_CACHE_DIR)/" .. key .. "/" .. n
    end
    local cmd = string.format(
        "\t@REPLACE_KEY=%s bash %s || (echo '==> FAILED: key=%s' >&2; cat $(REPLACE_CACHE_DIR)/%s/both >&2; exit 1)",
        key,
        runner_path,
        key,
        key
    )
    rules[#rules + 1] = table.concat(targets, " ") .. " &: " .. table.concat(prereqs, " ") .. "\n" .. cmd
end

-- Emit a make rule for an include= key. The included file is the rule's only
-- prereq. The filter writes cache/<key>/both with the post-processed body at
-- filter time (idempotently). The recipe touches the primary so an edit to
-- the included file invalidates the primary target and cascades to
-- consumers; pass 3 rewrites cache/<key>/both with the new content while
-- rebuilding README.md.
function emit_include_rule(key, include_abs)
    local primary = "$(REPLACE_CACHE_DIR)/" .. key .. "/both"
    rules[#rules + 1] = primary .. ": " .. include_abs .. "\n\t@touch " .. primary
end

-- Lazily define key and all its transitive depends= in DFS order.
local function ensure_defined(key)
    if defined[key] then
        return
    end
    assertf(not defining[key], "key=%s: dependency cycle", key)
    local p = pending[key]
    assertf(p, "key=%s: not defined", key)
    defining[key] = true
    for _, d in ipairs(p.deps) do
        ensure_defined(d.base)
    end
    for _, s in ipairs(p.vars) do
        if s.kind ~= "contents" then
            ensure_defined(s.base)
        end
    end
    define_script(key, p.attr, p.body, p.classes, p.deps, p.vars, p.include_abs)
    defining[key] = nil
end

-- Pandoc gfm renders a classless CodeBlock as 4-space-indented; force fence.
local function force_fenced(el)
    local has_attrs = #el.attr.attributes > 0
    if #el.classes == 0 and not has_attrs and el.identifier == "" then
        el.classes = { "text" }
    end
end

-- Parse the replace= value into (kind, a, b).
-- kind == "null"     -> drop the block
-- kind == "source"   -> a = region string or nil
-- kind == "stream"   -> a = "stdout"|"stderr"|"both" (own key only)
-- kind == "artifact" -> a = artifact name (own key only; must be in outputs=)
-- kind == "cross"    -> a = K, b = thing (stream/artifact/source[/region])
local function parse_replace_target(val, self_key)
    if val == "null" then
        return "null"
    end
    if val == "source" then
        return "source", nil
    end
    if val == "stdout" or val == "stderr" or val == "both" then
        return "stream", val
    end
    if val:sub(1, 7) == "source/" then
        local region = val:sub(8)
        assertf(region ~= "null", "replace=source/null: 'null' is a reserved marker name, not a region")
        return "source", region
    end
    if self_key and outputs_t[self_key] and outputs_t[self_key][val] then
        return "artifact", val
    end
    local k, rest = val:match("^([%w._%-]+)/(.+)$")
    if k then
        return "cross", k, rest
    end
    if val:match("^[%w._%-]+$") then
        return "cross", val, "both"
    end
    error("replace=" .. val .. ": unrecognized value")
end

local render_source -- forward declaration (render_source <-> cross_read mutual ref)

local function cross_read(K, thing, vars_spec, label)
    ensure_defined(K)
    assertf(defined[K], "%s: key '%s' not defined", label, K)
    -- include= keys produce only cache/<K>/both (the body). Reject any thing
    -- other than K, K/both, K/path, K/both/path with a clear error.
    if pending[K] and pending[K].include_abs then
        local v = thing == "both" or thing == "path" or thing == "both/path"
        assertf(v, "%s: include= key '%s' only supports K, K/both, K/path, K/both/path (got K/%s)", label, K, thing)
    end
    if thing == "path" then
        return REPLACE_CACHE_DIR .. "/" .. K
    end
    local sub_path = thing:match("^(.+)/path$")
    if sub_path then
        assertf(
            not no_runner[K],
            "%s: runner=%s is not in LANG_INFO; cannot consume cache/%s/%s",
            label,
            no_runner[K],
            K,
            sub_path
        )
        return REPLACE_CACHE_DIR .. "/" .. K .. "/" .. sub_path
    end
    -- globals/NAME renders the value of `-M NAME=...`.
    if K == "globals" then
        check_identifier(thing:gsub("%-", "_"), label .. ": globals/" .. thing)
        return read_output(K, thing, label)
    end
    if thing == "source" then
        assertf(sources[K], "%s: replace=source: source not stored for '%s'", label, K)
        return render_source(sources[K], nil, vars_spec, label)
    end
    if thing:sub(1, 7) == "source/" then
        local region = thing:sub(8)
        assertf(sources[K], "%s: replace=source: source not stored for '%s'", label, K)
        return render_source(sources[K], region, vars_spec, label)
    end
    if thing == "stdout" or thing == "stderr" or thing == "both" then
        return read_output(K, thing, label)
    end
    assertf(outputs_t[K] and outputs_t[K][thing], "%s: key '%s' has no artifact '%s'", label, K, thing)
    return read_output(K, thing, label)
end

render_source = function(text, region, vars_spec, label)
    text = strip_null_regions(text, label)
    if region or text:find("[#%-/]+%s*docs:begin") then
        text = extract_region(text, region, label)
    end
    local pairs_list = {}
    for _, p in ipairs(vars_spec or {}) do
        if p.kind == "contents" then
            ensure_defined(p.base)
            local val
            if p.sub == "source" then
                val = render_source(sources[p.base], nil, nil, label .. ": vars=" .. p.var)
            elseif p.sub:sub(1, 7) == "source/" then
                local r = p.sub:sub(8)
                val = render_source(sources[p.base], r, nil, label .. ": vars=" .. p.var)
            else
                val = read_output(p.base, p.sub, label .. ": vars=" .. p.var .. "->" .. p.raw)
            end
            pairs_list[#pairs_list + 1] = { var = p.var, value = val }
        end
    end
    return vars.apply(text, pairs_list)
end

-- The filter uses two passes. Pass 1 (collect) uses pandoc.walk_block to
-- record every key= block body without resolving anything. Pass 2
-- (walk_blocks) renders in document order, lazily defining each key on
-- demand via DFS through depends=. Both replace= and depends= are therefore
-- order-independent.

local function process_codeblock(el)
    local attr = el.attr.attributes
    local key, replace = attr.key, attr.replace
    local has_include = attr.include ~= nil
    if not key and not replace then
        return el
    end

    local enabled = is_enabled(attr)
    if enabled then
        if key then
            ensure_defined(key)
        end
        -- include= blocks produce the included body as their output; default
        -- to replace=both, and forbid forms that don't apply (no stdout/stderr/
        -- artifact/source for include= keys).
        if has_include and not replace then
            replace = "both"
        end
        assertf(replace, "%s: replace= attribute required", key and "key=" .. key or "CodeBlock")
        assertf(
            not has_include or replace == "both" or replace == "null",
            "key=%s: include= block only supports replace=both or replace=null (got replace=%s)",
            key,
            replace
        )
    end

    local vars_spec = parse_vars(attr.vars)
    attr.key = nil
    attr.ref = nil
    attr.depends = nil
    attr.sequential = nil
    attr.outputs = nil
    attr.replace = nil
    attr.block = nil
    attr.vars = nil
    attr.enabled = nil
    attr.include = nil
    attr.runner = nil

    if not enabled then
        force_fenced(el)
        return el
    end

    if replace == "null" then
        return {}
    end

    local label = key and "key=" .. key or "replace=" .. replace
    local kind, a, b = parse_replace_target(replace, key)

    if kind == "null" then
        return {}
    end
    if kind == "source" then
        assertf(key, "%s: replace=source requires key=", label)
        el.text = render_source(sources[key], a, vars_spec, label)
        force_fenced(el)
        return el
    end
    if kind == "stream" or kind == "artifact" then
        assertf(key, "%s: replace=%s requires key=", label, a)
        el.text = read_output(key, a, label)
        force_fenced(el)
        return el
    end
    if kind == "cross" then
        el.text = cross_read(a, b, vars_spec, label)
        force_fenced(el)
        return el
    end
    error(label .. ": unknown replace= value")
end

local function process_code(el)
    local attr = el.attr.attributes
    local replace = attr.replace
    if not replace then
        return el
    end
    assertf(not attr.include, "inline Code: include= not supported (use key= CodeBlock)")
    assertf(not attr.runner, "inline Code: runner= not supported (use key= CodeBlock)")
    local enabled = is_enabled(attr)
    attr.replace = nil
    attr.enabled = nil
    attr.include = nil
    if not enabled then
        return el
    end
    local label = "inline Code replace=" .. replace
    local kind, a, b = parse_replace_target(replace, nil)
    if kind == "cross" then
        el.text = cross_read(a, b, nil, label)
        return el
    end
    error(label .. ": only cross-block replace= (K or K/<thing>) supported on inline Code")
end

local function process_span(el)
    local attr = el.attr.attributes
    local replace = attr.replace
    if not replace then
        return el
    end
    assertf(not attr.include, "inline Span: include= not supported (use key= CodeBlock)")
    assertf(not attr.runner, "inline Span: runner= not supported (use key= CodeBlock)")
    local enabled = is_enabled(attr)
    local code = attr.code
    attr.replace = nil
    attr.enabled = nil
    attr.include = nil
    attr.code = nil
    if not enabled then
        return el
    end
    local label = "inline Span replace=" .. replace
    local kind, a, b = parse_replace_target(replace, nil)
    if kind == "cross" then
        local suffix = pandoc.utils.stringify(el.content)
        local text = cross_read(a, b, nil, label) .. suffix
        if code == "no" or code == "false" or code == "0" then
            return pandoc.Str(text)
        end
        return pandoc.Code(text)
    end
    error(label .. ": only cross-block replace= (K or K/<thing>) supported on inline Span")
end

local INLINE_FILTER = { Code = process_code, Span = process_span }

-- Walk a list of blocks in document order, processing CodeBlocks via
-- process_codeblock and recursing into block containers (Div, BlockQuote,
-- list items) so nested key=/replace= blocks are handled. Inline filters run
-- on every visited block.
local walk_blocks

local function walk_block(b)
    if b.tag == "CodeBlock" then
        return process_codeblock(b)
    end
    if b.content and (b.tag == "Div" or b.tag == "BlockQuote") then
        b.content = walk_blocks(b.content)
        return pandoc.walk_block(b, INLINE_FILTER)
    end
    if (b.tag == "BulletList" or b.tag == "OrderedList") and b.content then
        for i, item in ipairs(b.content) do
            b.content[i] = walk_blocks(item)
        end
        return pandoc.walk_block(b, INLINE_FILTER)
    end
    return pandoc.walk_block(b, INLINE_FILTER)
end

walk_blocks = function(blocks)
    local out = {}
    for _, b in ipairs(blocks) do
        local r = walk_block(b)
        if type(r) == "table" and not r.tag then
            for _, x in ipairs(r) do
                out[#out + 1] = x
            end
        elseif r then
            out[#out + 1] = r
        end
    end
    return out
end

local function sorted(t)
    local r = {}
    for k in pairs(t) do
        r[#r + 1] = k
    end
    table.sort(r)
    return r
end

local function build_makefile_text()
    local out = { deps_target, ":" }
    for _, c in ipairs(sorted(consumed)) do
        out[#out + 1] = " $(REPLACE_CACHE_DIR)/"
        out[#out + 1] = c
    end
    out[#out + 1] = "\n"
    for _, r in ipairs(rules) do
        out[#out + 1] = r
        out[#out + 1] = "\n"
    end
    return table.concat(out)
end

local function collect_codeblock(b)
    local key = b.attr.attributes.key
    if not key then
        return
    end
    if not is_enabled(b.attr.attributes) then
        return
    end
    check_identifier(key, "key=" .. key)
    assertf(key ~= "globals", "key=globals: 'globals' is a reserved pseudo-key")
    assertf(not pending[key], "key=%s: duplicate definition", key)
    local include = b.attr.attributes.include
    local body = b.text
    local include_abs
    if include then
        assertf(body == "", "key=%s: include=%s: block body must be empty when include= is set", key, include)
        -- Disambiguate FILE/<region> from a plain path: try the whole value as a
        -- file path first. If that fails and the value contains a '/', split on
        -- the last '/' and treat the RHS as a region name within the LHS file.
        local file_path, region
        local f = io.open(RECIPES_DIR .. "/" .. include, "r")
        if f then
            f:close()
            file_path = include
        else
            local lhs, rhs = include:match("^(.+)/([^/]+)$")
            assertf(lhs, "key=%s: include=%s: file not found", key, include)
            file_path = lhs
            region = rhs
        end
        include_abs = RECIPES_DIR .. "/" .. file_path
        local file_content = read_file(include_abs, "key=" .. key .. " include=" .. include)
        if region then
            body = extract_region(file_content, region, "key=" .. key .. " include=" .. include)
        else
            body = strip_all_markers(strip_null_regions(file_content, "key=" .. key .. " include=" .. include))
        end
    end
    local seq = parse_sequential(b.attr.attributes.sequential)
    assertf(not (include and seq), "key=%s: sequential= not allowed on include= keys", key)
    local deps = parse_depends(b.attr.attributes.depends)
    if seq then
        local prev = sequential[seq]
        if prev then
            deps[#deps + 1] = { base = prev, sub = nil }
        end
        sequential[seq] = key
    end
    pending[key] = {
        attr = b.attr.attributes,
        body = body,
        classes = b.classes,
        deps = deps,
        vars = parse_vars(b.attr.attributes.vars),
        include_abs = include_abs,
    }
end

local function collect(blocks)
    pandoc.walk_block(pandoc.Div(blocks), { CodeBlock = collect_codeblock })
end

function Pandoc(doc)
    local m = doc.meta["write-user-dependencies"]
    deps_target = m and pandoc.utils.stringify(m) or nil
    local dr = doc.meta["default-replace"]
    if dr ~= nil then
        local v = pandoc.utils.stringify(dr)
        default_enabled = v == "true" or v == "yes" or v == "1"
    end
    local globals_dir = REPLACE_CACHE_DIR .. "/globals"
    os.execute("mkdir -p '" .. globals_dir .. "'")
    for k, v in pairs(doc.meta) do
        if k:match("^[%a_][%w_%-]*$") then
            local f = io.open(globals_dir .. "/" .. k, "w")
            if f then
                f:write(pandoc.utils.stringify(v))
                f:close()
            end
        end
    end
    defined["globals"] = true
    outputs_t["globals"] = {}
    sources["globals"] = ""
    collect(doc.blocks)
    doc.blocks = walk_blocks(doc.blocks)
    if deps_target then
        doc.blocks = { pandoc.RawBlock("plain", build_makefile_text()) }
    end
    return doc
end

return { { Pandoc = Pandoc } }
