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

#ifndef ASIO_CONFIG_H
#define ASIO_CONFIG_H

// Disable threads to avoid potential issues fork()
#define BOOST_ASIO_DISABLE_THREADS
// Use select-based based implementation to avoid potential issues with fork()
#define BOOST_ASIO_DISABLE_EPOLL
#define BOOST_ASIO_DISABLE_EVENTFD

#endif
