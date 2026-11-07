// Freestanding implementations of the libc functions libcmt's merkle.c and keccak.c call.
#include <string.h>
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char) c;
    return dst;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (; n--; ++x, ++y)
        if (*x != *y) return *x - *y;
    return 0;
}
size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}
