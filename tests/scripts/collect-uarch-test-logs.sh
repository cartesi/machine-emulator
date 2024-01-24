#!/bin/bash

# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
#

mkdir -m 755 -p /tmp/uarch-riscv-tests-json-logs
uarch-riscv-tests --output-dir=/tmp/logs --proofs --proofs-frequency=1 json-step-logs
uarch-riscv-tests --output-dir=/tmp/logs --proofs json-reset-log
tar -czf uarch-riscv-tests-json-logs.tar.gz -C /tmp uarch-riscv-tests-json-logs
