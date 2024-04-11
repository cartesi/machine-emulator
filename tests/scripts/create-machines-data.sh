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

set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
data_path=${CARTESI_DATA_PATH:-$PWD}/

# valid advance
cast calldata "EvmAdvance(uint256,address,address,uint256,uint256,uint256,bytes)" \
  0x0000000000000000000000000000000000000001 \
  0x0000000000000000000000000000000000000002 \
  0x0000000000000000000000000000000000000003 \
  0x0000000000000000000000000000000000000004 \
  0x0000000000000000000000000000000000000005 \
  0x0000000000000000000000000000000000000006 \
  0x`echo "advance-0" | xxd -p -c0` | xxd -r -p > "$data_path"valid-advance.bin

# swapped (first and second) fields advance
cast calldata "EvmAdvance(address,uint256,address,uint256,uint256,uint256,bytes)" \
  0x0000000000000000000000000000000000000001 \
  0x0000000000000000000000000000000000000002 \
  0x0000000000000000000000000000000000000003 \
  0x0000000000000000000000000000000000000004 \
  0x0000000000000000000000000000000000000005 \
  0x0000000000000000000000000000000000000006 \
  0x`echo "advance-0" | xxd -p -c0` | xxd -r -p > "$data_path"swapped-fields-advance.bin

echo "inspect-0" > "$data_path"valid-inspect.bin
