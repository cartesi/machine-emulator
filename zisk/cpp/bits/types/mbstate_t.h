// Minimal mbstate_t for freestanding ZisK environment
// This is included by libc++'s __mbstate_t.h via __has_include
#ifndef _BITS_TYPES_MBSTATE_T_H
#define _BITS_TYPES_MBSTATE_T_H

// mbstate_t is already defined in zisk-runtime.h which is force-included
// This file just needs to exist to satisfy __has_include check

#endif // _BITS_TYPES_MBSTATE_T_H
