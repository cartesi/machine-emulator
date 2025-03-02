#ifndef HTIF_UTIL_H
#define HTIF_UTIL_H
#include <address-range-defines.h>
#include <htif-defines.h>

/* from: https://www.cartesi.io/en/docs/machine/target/architecture/
 * 1. start by writing 0 to fromhost
 * 2. write the request to tohost     (from a0)
 * 3. read the response from fromhost (into a0)
 *
 * with the following memory layout:
 * +------+----------+
 * | 0x00 | tohost   |
 * | 0x08 | fromhost |
 * | 0x10 | ihalt    |
 * | 0x18 | iconsole |
 * | 0x20 | iyield   |
 * +------+----------+
 *
 * htif register offsets: */
#define O_TOHOST   0x00
#define O_FROMHOST 0x08
#define O_IHALT    0x10
#define O_ICONSOLE 0x18
#define O_IYIELD   0x20

// Construct a HTIF constant value from `dev`, `cmd` and `data` that can be used
// in conjunction with htif_call.
#define htif_const(dev, cmd, data) \
    (((dev) << 56UL) | (((cmd) & 0xff) << 48UL) | (((data) & 0xffffffffffUL)))

// Construct a htif_const `data` constant from `reason` and `data` fields.
#define htif_yield_const(reason, data) \
    ((((reason) & 0xffffUL) << 32UL) | (((data) & 0xffffffffUL)))

// Issue a HTIF call with `ireg` as the input, place the output in `oreg`.
// NOTE: `base` will be used as scratch register
#define htif_call(base, ireg, oreg) \
    li base, AR_HTIF_START_DEF; \
    sd zero, O_FROMHOST (base); \
    sd ireg, O_TOHOST   (base); \
    ld oreg, O_FROMHOST (base)

// Issue a HTIF yield call with `cmd`, `reason` and `data` as a constants.
// Result in a0
#define htif_yield(cmd, reason, data) \
    li t1, htif_const(HTIF_DEV_YIELD_DEF, cmd, htif_yield_const(reason, data)); \
    htif_call(t0, t1, a0)

// Issue a HTIF exit call with `retval` as a constant.
#define htif_exit(retval) \
    li t1, htif_const(HTIF_DEV_HALT_DEF, HTIF_HALT_CMD_HALT_DEF, ((retval) << 1) | 0x01); \
    htif_call(t0, t1, a0)

// Issue a HTIF putchar with `data` as a constant.
#define htif_console_putchar(data) \
    li t1, htif_const(HTIF_DEV_CONSOLE_DEF, HTIF_CONSOLE_CMD_PUTCHAR_DEF, data); \
    htif_call(t0, t1, a0)

// Issue a HTIF getchar
// Result in a0
#define htif_console_getchar() \
    li t1, htif_const(HTIF_DEV_CONSOLE_DEF, HTIF_CONSOLE_CMD_GETCHAR_DEF, 0); \
    htif_call(t0, t1, a0); \
    andi a0, a0, 0xFF; \
    addi a0, a0, -1

#endif /* HTIF_UTIL_H */
