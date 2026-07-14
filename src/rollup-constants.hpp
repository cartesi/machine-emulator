// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef ROLLUP_CONSTANTS_HPP
#define ROLLUP_CONSTANTS_HPP

#include <cstdint>

#include "rollup-defines.h"

namespace cartesi {

enum rollup_constants : uint64_t {
    ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE_DEF,
    ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE_DEF,
    ROLLUP_LOG2_MAX_OUTPUT_COUNT = ROLLUP_LOG2_MAX_OUTPUT_COUNT_DEF,
    ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH_DEF,
};

} // namespace cartesi

#endif
