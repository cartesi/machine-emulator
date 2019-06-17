#include <string.h>

#include <pma-defines.h>

#include "util.h"

volatile extern uint64_t tohost;
volatile extern uint64_t fromhost;

static char digits[] = "0123456789abcdef";

int ulltoa(char *str, unsigned long long value, int base)
{
    int p = 0, i = 0, j = 0;
    char c;

    if (base != 10 && base != 16)
        return -1;

    do {
        str[p++] = digits[value % base];
    } while (value /= base);
    str[p] = '\0';

    // reversing
    for (i = 0, j = p-1; i < j; i++, j--) {
	c = str[i];
	str[i] = str[j];
	str[j] = c;
    }
    return p - 1;
}

void do_tohost(uint64_t tohost_value)
{
	while (tohost)
		fromhost = 0;
	tohost = tohost_value;
}

void cputchar(int x)
{
	do_tohost(0x0101000000000000 | (unsigned char)x);
}

void cputs(const char* s)
{
	while (*s)
		cputchar(*s++);
}

