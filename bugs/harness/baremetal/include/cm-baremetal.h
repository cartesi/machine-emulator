/* Minimal bare-metal runtime for Cartesi Machine guests (no Linux, no SBI).
 * Audit harness: bugs/harness/baremetal. Build with build.sh, which puts the emulator's src/ on the include
 * path so the device constants come from the audited headers themselves.
 *
 * The machine starts at pc = AR_RAM_START (0x80000000) in M-mode; crt0.S sets the stack and calls main().
 * HTIF protocol (manual, "HTIF"): write 0 to fromhost, write the request to tohost, read the answer from
 * fromhost.
 */
#ifndef CM_BAREMETAL_H
#define CM_BAREMETAL_H

#include <stddef.h>
#include <stdint.h>

#include <address-range-defines.h>
#include <htif-defines.h>

#define CM_HTIF_TOHOST ((volatile uint64_t *) (AR_HTIF_START_DEF + 0x00))
#define CM_HTIF_FROMHOST ((volatile uint64_t *) (AR_HTIF_START_DEF + 0x08))

#define CM_RX_BUFFER ((volatile uint8_t *) AR_CMIO_RX_BUFFER_START_DEF)
#define CM_TX_BUFFER ((volatile uint8_t *) AR_CMIO_TX_BUFFER_START_DEF)
#define CM_RX_BUFFER_SIZE (1UL << AR_CMIO_RX_BUFFER_LOG2_SIZE_DEF)
#define CM_TX_BUFFER_SIZE (1UL << AR_CMIO_TX_BUFFER_LOG2_SIZE_DEF)

#define CM_HASH_SIZE 32
#define CM_LOG2_MAX_OUTPUT_COUNT 63 /* cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT */

static inline uint64_t cm_htif_const(uint64_t dev, uint64_t cmd, uint64_t data) {
    return (dev << HTIF_DEV_SHIFT_DEF) | ((cmd & 0xff) << HTIF_CMD_SHIFT_DEF) | (data & 0xffffffffffffUL);
}

static inline uint64_t cm_htif_call(uint64_t request) {
    *CM_HTIF_FROMHOST = 0;
    *CM_HTIF_TOHOST = request;
    return *CM_HTIF_FROMHOST;
}

/* Halt the machine (iflags_H) with an exit code; never returns. */
static inline __attribute__((noreturn)) void cm_halt(uint32_t code) {
    for (;;) {
        cm_htif_call(cm_htif_const(HTIF_DEV_HALT_DEF, HTIF_HALT_CMD_HALT_DEF, ((uint64_t) code << 1) | 1));
    }
}

static inline void cm_putchar(int c) {
    cm_htif_call(cm_htif_const(HTIF_DEV_CONSOLE_DEF, HTIF_CONSOLE_CMD_PUTCHAR_DEF, (uint8_t) c));
}

static inline void cm_puts(const char *s) {
    while (*s) {
        cm_putchar(*s++);
    }
}

/* Yield. Returns the fromhost value; for a manual yield the answer is the next request:
 * reason = (r >> 32) & 0xffff (HTIF_YIELD_REASON_ADVANCE_STATE / _INSPECT_STATE), length = r & 0xffffffff. */
static inline uint64_t cm_yield(uint64_t cmd, uint16_t reason, uint32_t data) {
    uint64_t d = ((uint64_t) reason << HTIF_REASON_SHIFT_DEF) | data;
    return cm_htif_call(cm_htif_const(HTIF_DEV_YIELD_DEF, cmd, d));
}

static inline uint64_t cm_yield_manual(uint16_t reason, uint32_t data) {
    return cm_yield(HTIF_YIELD_CMD_MANUAL_DEF, reason, data);
}

static inline uint64_t cm_yield_automatic(uint16_t reason, uint32_t data) {
    return cm_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, reason, data);
}

static inline uint16_t cm_request_reason(uint64_t fromhost) {
    return (uint16_t) ((fromhost >> HTIF_REASON_SHIFT_DEF) & 0xffff);
}

static inline uint32_t cm_request_length(uint64_t fromhost) {
    return (uint32_t) (fromhost & 0xffffffffUL);
}

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

/* keccak256 (Ethereum flavor, 0x01 padding) */
void cm_keccak256(const void *data, size_t len, uint8_t out[CM_HASH_SIZE]);
void cm_keccak256_pair(const uint8_t a[CM_HASH_SIZE], const uint8_t b[CM_HASH_SIZE], uint8_t out[CM_HASH_SIZE]);

/* Outputs Merkle tree of height CM_LOG2_MAX_OUTPUT_COUNT, leaves keccak256(output), pristine leaf = 32 zero bytes
 * (same convention as cartesi.hash-tree frontier with "keccak256"). */
typedef struct {
    uint8_t level[CM_LOG2_MAX_OUTPUT_COUNT + 1][CM_HASH_SIZE];
    uint8_t filled[CM_LOG2_MAX_OUTPUT_COUNT + 1];
    uint64_t count;
} cm_outputs_tree;

void cm_outputs_init(cm_outputs_tree *t);
void cm_outputs_push(cm_outputs_tree *t, const uint8_t leaf[CM_HASH_SIZE]);
void cm_outputs_root(const cm_outputs_tree *t, uint8_t root[CM_HASH_SIZE]);

/* Rollup helpers built on the above:
 *   cm_rollup_accept(root)  writes root to the tx buffer and yields manual RX_ACCEPTED with length 32
 *   cm_rollup_reject()      yields manual RX_REJECTED with length 0
 *   cm_rollup_emit_output() writes bytes to the tx buffer and yields automatic TX_OUTPUT
 *   cm_rollup_emit_report() writes bytes to the tx buffer and yields automatic TX_REPORT
 *   cm_rollup_exception()   writes bytes to the tx buffer and yields manual TX_EXCEPTION
 * The manual ones return the next request (fromhost). */
uint64_t cm_rollup_accept(const uint8_t root[CM_HASH_SIZE]);
uint64_t cm_rollup_reject(void);
void cm_rollup_emit_output(const void *data, uint32_t len);
void cm_rollup_emit_report(const void *data, uint32_t len);
uint64_t cm_rollup_exception(const void *data, uint32_t len);

#endif
