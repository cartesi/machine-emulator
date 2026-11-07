// A correctly designed bare-metal rollup application (section 2 of THREAT_MODEL.md): it reads a
// little-endian u32 N from the first 4 bytes of each advance-state input, emits N notices (each the
// rollup interface's Notice(bytes) ABI encoding of a 1-byte payload, exactly what libcmt's
// cmt_rollup_emit_notice writes), keeps the outputs Merkle tree with libcmt's own merkle/keccak code,
// and accepts the input with the outputs Merkle root in the transmit buffer. Think of an airdrop or
// echo application that emits one output per item of its payload.
#include <stdint.h>
#include <string.h>
#include "libcmt/merkle.h"

#define TOHOST ((volatile uint64_t *) 0x40008000)
#define RX ((const volatile uint8_t *) 0x60000000)
#define TX ((uint8_t *) 0x60800000)
#define NOTICE_LENGTH 100

static cmt_merkle_t merkle;

static void yield(uint64_t cmd, uint64_t reason, uint64_t data) {
    *TOHOST = (2ull << 56) | (cmd << 48) | (reason << 32) | data;
}

// Notice(bytes): funsel c258d6e5, offset 0x20, length 1, one data byte padded to 32 bytes.
static void put_notice(uint8_t *out, uint8_t byte) {
    memset(out, 0, NOTICE_LENGTH);
    out[0] = 0xc2;
    out[1] = 0x58;
    out[2] = 0xd6;
    out[3] = 0xe5;
    out[4 + 31] = 0x20;
    out[36 + 31] = 1;
    out[68] = byte;
}

int main(void) {
    cmt_merkle_init(&merkle);
    for (;;) {
        cmt_merkle_get_root_hash(&merkle, TX);
        yield(1, 1, 32); // manual yield, accepted, 32-byte outputs Merkle root
        uint32_t n = (uint32_t) RX[0] | ((uint32_t) RX[1] << 8) | ((uint32_t) RX[2] << 16) | ((uint32_t) RX[3] << 24);
        for (uint32_t i = 0; i < n; ++i) {
            put_notice(TX, 0);
            yield(0, 2, NOTICE_LENGTH); // automatic yield, tx-output
            cmt_merkle_push_back_data(&merkle, NOTICE_LENGTH, TX);
        }
    }
}
