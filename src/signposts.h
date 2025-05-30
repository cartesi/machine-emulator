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

#ifndef SIGNPOSTS_H
#define SIGNPOSTS_H

#if defined(__APPLE__) && defined(ISSUE_SIGNPOSTS)
#define HAS_SIGNPOSTS
#endif

#ifdef HAS_SIGNPOSTS

#include <os/log.h>
#include <os/signpost.h>

#define CONCAT(x, y) x##y

#define SCOPED_SIGNPOST_IMPL(log, id, name, line, ...)                                                                 \
    struct CONCAT(scoped_signpost_, line) {                                                                            \
        os_log_t m_log;                                                                                                \
        os_signpost_id_t m_id;                                                                                         \
        CONCAT(scoped_signpost_, line)(os_log_t l, os_signpost_id_t i) : m_log(l), m_id(i) {                           \
            os_signpost_interval_begin(l, i, name, __VA_ARGS__);                                                       \
        }                                                                                                              \
        ~CONCAT(scoped_signpost_, line)() {                                                                            \
            os_signpost_interval_end(m_log, m_id, name, __VA_ARGS__);                                                  \
        }                                                                                                              \
    } CONCAT(signpost_instance_, line)(log, id)

#define SCOPED_SIGNPOST(log, id, name, ...) SCOPED_SIGNPOST_IMPL(log, id, name, __LINE__, __VA_ARGS__)

#else // HAS_SIGNPOSTS

#define SCOPED_SIGNPOST(log, id, name, ...)

#endif // HAS_SIGNPOSTS

#endif // SIGNPOSTS_H
