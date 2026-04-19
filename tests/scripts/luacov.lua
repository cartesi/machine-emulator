-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- LuaCov configuration for cartesi-machine.lua coverage.
-- Loaded via LUACOV_CONFIG env variable when -lluacov is preloaded.

return {
	statsfile = os.getenv("LUACOV_STATS") or "luacov.stats.out",
	include = { "src/cartesi%-machine$" },
	savestepsize = 0,
}
