#ifndef RTC_H
#define RTC_H

#include <cstdint>

#define RTC_FREQ_DIV 100  // Set in stone in whitepaper

static inline uint64_t rtc_cycle_to_time(uint64_t cycle) {
    return cycle / RTC_FREQ_DIV;
}

static inline uint64_t rtc_time_to_cycle(uint64_t time) {
    return time * RTC_FREQ_DIV;
}

#endif
