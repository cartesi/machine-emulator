#!/usr/bin/env lua5.4

-- Copyright 2023 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local lester = require("cartesi.third-party.lester")

-- Parse arguments from command line.
lester.parse_args()

require("spec-hash-functions")
require("spec-hash-tree")
require("spec-collect-hashes")
require("spec-backing-stores")
require("spec-runtime-console")

lester.report() -- Print overall statistic of the tests run.
lester.exit() -- Exit with success if all tests passed.
