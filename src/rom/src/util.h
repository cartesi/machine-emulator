#ifndef UTIL_H
#define UTIL_H

#include <cstdint>

void do_tohost(uint64_t tohost_value);
void cputchar(int x);
void cputs(const char *s);
int ulltoa(char *str, unsigned long long value, int base);

#endif /* end of UTIL_H */
