// Freestanding stand-in for the few libc declarations libcmt's merkle.c and keccak.c use.
#pragma once
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
