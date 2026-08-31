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

/// \file
/// \brief libFuzzer harness for the binary step-log decoder.
///
/// The step log is the attacker-facing input of every replay verifier: the log
/// bytes arrive from an untrusted prover and step_log::decode must reject every
/// malformed image with an exception, never with memory corruption or a wrong
/// accept. This harness feeds arbitrary bytes to decode, which exercises the
/// header parsing, the per-count size bounds, the page/node ordering and
/// disjointness validation, and the initial-root Merkle recompute.
///
/// Scope: the parser and pre-state validation only; the replay behind it needs
/// verifier arguments this harness does not model.
/// Seed the corpus with recorded fixture logs (make fuzz-step-log-seed-corpus)
/// so mutations explore the validation paths deeply instead of dying on the
/// signature check.

#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>

#include <step-log.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // decode requires an 8-aligned, mutable image (it rehashes pages into their
    // scratch slots in place), so copy the input into an aligned buffer.
    const size_t words = size / 8 + 1;
    const std::unique_ptr<uint64_t[]> buffer{new uint64_t[words]};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *image = reinterpret_cast<unsigned char *>(buffer.get());
    std::memcpy(image, data, size);

    try {
        auto log = cartesi::step_log::decode(image, size);
        // A structurally valid log (an unmutated seed) also exercises the
        // queries and the post-state walk; both must be exception-safe.
        log.try_find_page(log.pages[0].index << 12);
        log.try_find_node(0);
        log.compute_root_hash();
    } catch (const std::exception &) {
        // rejection is the expected outcome for nearly every input
    }
    return 0;
}
