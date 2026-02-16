// Minimal inttypes.h for freestanding ZisK environment
// Required by libc++'s <cinttypes> - must exist as a separate file
#ifndef _INTTYPES_H
#define _INTTYPES_H
#define _LIBCPP_INTTYPES_H

#include <stdint.h>

// Format specifiers for printf (rv64)
// Only defining what's actually used in the codebase
#define PRId32  "d"
#define PRId64  "ld"
#define PRIu64  "lu"
#define PRIx32  "x"
#define PRIx64  "lx"

// imaxdiv_t required by <cinttypes> even if not called
typedef struct { intmax_t quot, rem; } imaxdiv_t;

#endif // _INTTYPES_H
