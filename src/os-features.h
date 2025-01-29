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

#ifndef OS_FEATURES_H
#define OS_FEATURES_H

#if !defined(NO_TTY)
#define HAVE_TTY
#endif

#if !defined(NO_THREADS)
#define HAVE_THREADS
#define THREAD_LOCAL thread_local
#else
#define THREAD_LOCAL
#endif

#if !defined(NO_TERMIOS) && !defined(_WIN32) && !defined(__wasi__)
#define HAVE_TERMIOS
#endif

#if !defined(NO_IOCTL) && !defined(_WIN32) && !defined(__wasi__)
#define HAVE_IOCTL
#endif

#if !defined(NO_MMAP) && !defined(_WIN32) && !defined(__wasi__)
#define HAVE_MMAP
#endif

#if !defined(NO_MKDIR)
#define HAVE_MKDIR
#endif

#if !defined(NO_TUNTAP) && defined(__linux__)
#define HAVE_TUNTAP
#endif

#if !defined(NO_SLIRP) && !defined(__wasi__)
#define HAVE_SLIRP
#endif

#if !defined(NO_SIGACTION) && !defined(__wasi__) && !defined(_WIN32)
#define HAVE_SIGACTION
#endif

#if !defined(NO_SELECT)
#define HAVE_SELECT
#endif

#if !defined(NO_POSIX_FILE) && !defined(__wasi__)
#define HAVE_POSIX_FS
#endif

#if !defined(NO_USLEEP) && (defined(__unix__) || defined(__APPLE__))
#define HAVE_USLEEP
#endif

#if !defined(NO_FORK) && (defined(__linux__) || defined(__unix__) || defined(__APPLE__)) && !defined(__wasi__)
#define HAVE_FORK
#endif

#endif
