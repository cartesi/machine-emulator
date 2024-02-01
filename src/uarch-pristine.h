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

#ifndef UARCH_PRISTINE_H
#define UARCH_PRISTINE_H

/// \brief Embedded pristine uarch ram image. This symbol is created by "xxd"
extern "C" const unsigned char uarch_pristine_ram[];

/// \brief Length of the embedded pristine uarch ram image. This symbol is created by "xxd"
extern "C" const unsigned int uarch_pristine_ram_len;

/// \brief Embedded pristine uarch ram image. This symbol is created by "compute-uarch-pristine-hash"
extern "C" const unsigned char uarch_pristine_hash[];

/// \brief Length of the embedded pristine uarch ram image. This symbol is created by "compute-uarch-pristine-hash"
extern "C" const unsigned int uarch_pristine_hash_len;

#endif // UARCH_PRISTINE_H
