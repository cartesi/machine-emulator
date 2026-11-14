/* Bare-metal runtime: libc subset, keccak256, outputs Merkle tree, rollup helpers. */
#include "cm-baremetal.h"

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    uint8_t *d = dst;
    while (n--) {
        *d++ = (uint8_t) c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return x[i] < y[i] ? -1 : 1;
        }
    }
    return 0;
}

/* ---------------- keccak-f[1600] ---------------- */
static const uint64_t keccak_rc[24] = {0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL, 0x000000008000808bUL,
    0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL,
    0x8000000080008008UL};
static const unsigned keccak_rotc[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
    39, 61, 20, 44};
static const unsigned keccak_piln[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
    22, 9, 6, 1};

static inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static void keccakf(uint64_t st[25]) {
    uint64_t bc[5];
    for (int round = 0; round < 24; round++) {
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }
        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            unsigned j = keccak_piln[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, keccak_rotc[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        st[0] ^= keccak_rc[round];
    }
}

void cm_keccak256(const void *data, size_t len, uint8_t out[CM_HASH_SIZE]) {
    enum { RATE = 136 };
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    const uint8_t *in = data;
    uint8_t *s = (uint8_t *) st; /* little-endian lanes, RISC-V is little-endian */
    while (len >= RATE) {
        for (int i = 0; i < RATE; i++) {
            s[i] ^= in[i];
        }
        keccakf(st);
        in += RATE;
        len -= RATE;
    }
    for (size_t i = 0; i < len; i++) {
        s[i] ^= in[i];
    }
    s[len] ^= 0x01;
    s[RATE - 1] ^= 0x80;
    keccakf(st);
    memcpy(out, s, CM_HASH_SIZE);
}

void cm_keccak256_pair(const uint8_t a[CM_HASH_SIZE], const uint8_t b[CM_HASH_SIZE], uint8_t out[CM_HASH_SIZE]) {
    uint8_t buf[2 * CM_HASH_SIZE];
    memcpy(buf, a, CM_HASH_SIZE);
    memcpy(buf + CM_HASH_SIZE, b, CM_HASH_SIZE);
    cm_keccak256(buf, sizeof(buf), out);
}

/* ---------------- outputs Merkle tree (frontier) ---------------- */
void cm_outputs_init(cm_outputs_tree *t) {
    memset(t, 0, sizeof(*t));
}

void cm_outputs_push(cm_outputs_tree *t, const uint8_t leaf[CM_HASH_SIZE]) {
    uint8_t right[CM_HASH_SIZE];
    memcpy(right, leaf, CM_HASH_SIZE);
    int level = 0;
    while (t->filled[level]) {
        cm_keccak256_pair(t->level[level], right, right);
        t->filled[level] = 0;
        level++;
    }
    memcpy(t->level[level], right, CM_HASH_SIZE);
    t->filled[level] = 1;
    t->count++;
}

void cm_outputs_root(const cm_outputs_tree *t, uint8_t root[CM_HASH_SIZE]) {
    uint8_t zero[CM_HASH_SIZE];
    uint8_t acc[CM_HASH_SIZE];
    int have = 0;
    memset(zero, 0, sizeof(zero));
    for (int level = 0; level < CM_LOG2_MAX_OUTPUT_COUNT; level++) {
        if (t->filled[level]) {
            if (have) {
                cm_keccak256_pair(t->level[level], acc, acc);
            } else {
                cm_keccak256_pair(t->level[level], zero, acc);
                have = 1;
            }
        } else if (have) {
            cm_keccak256_pair(acc, zero, acc);
        }
        cm_keccak256_pair(zero, zero, zero);
    }
    memcpy(root, have ? acc : zero, CM_HASH_SIZE);
}

/* ---------------- rollup helpers ---------------- */
static void tx_write(const void *data, uint32_t len) {
    const uint8_t *p = data;
    for (uint32_t i = 0; i < len; i++) {
        CM_TX_BUFFER[i] = p[i];
    }
}

uint64_t cm_rollup_accept(const uint8_t root[CM_HASH_SIZE]) {
    tx_write(root, CM_HASH_SIZE);
    return cm_yield_manual(HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, CM_HASH_SIZE);
}

uint64_t cm_rollup_reject(void) {
    return cm_yield_manual(HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF, 0);
}

void cm_rollup_emit_output(const void *data, uint32_t len) {
    tx_write(data, len);
    cm_yield_automatic(HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF, len);
}

void cm_rollup_emit_report(const void *data, uint32_t len) {
    tx_write(data, len);
    cm_yield_automatic(HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT_DEF, len);
}

uint64_t cm_rollup_exception(const void *data, uint32_t len) {
    tx_write(data, len);
    return cm_yield_manual(HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION_DEF, len);
}
