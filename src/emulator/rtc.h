#ifndef RTC_H
#define RTC_H

#include <cstdint>

/// \file
/// \brief Real Time Clock

namespace cartesi {

/// \brief RTC constants
enum RTC_constants {
    RTC_FREQ_DIV  = 100  ///< Clock divisor is set stone in whitepaper
};

/// \brief Converts from cycle count to time count
/// \param cycle Cycle count
/// \returns Time count
static inline uint64_t rtc_cycle_to_time(uint64_t cycle) {
    return cycle / RTC_FREQ_DIV;
}

/// \brief Converts from time count to cycle count
/// \param time Time count
/// \returns Cycle count
static inline uint64_t rtc_time_to_cycle(uint64_t time) {
    return time * RTC_FREQ_DIV;
}

} // namespace cartesi

#endif
