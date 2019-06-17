#ifndef STRICT_ALIASING_H
#define STRICT_ALIASING_H

#include <cstring>

/// \file
/// \brief Enforcement of the strict aliasing rule

namespace cartesi {

/// \brief Writes a value to memory.
/// \tparam T Type of value.
/// \param p Where to write. Must be aligned to sizeof(T).
/// \param v Value to write.
template <typename T>
static inline void aliased_aligned_write(void *p, T v) {
    memcpy(__builtin_assume_aligned(p, sizeof(T)), &v, sizeof(T));
}

/// \brief Reads a value from memory.
/// \tparam T Type of value.
/// \param p Where to find value. Must be aligned to sizeof(T).
/// \returns Value.
template <typename T>
static inline T aliased_aligned_read(const void *p) {
    T v;
    memcpy(&v, __builtin_assume_aligned(p, sizeof(T)), sizeof(T));
    return v;
}

}

#endif
