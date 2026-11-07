/* R4-VARRANGE-1 proof-of-concept guest application.
 *
 * A correctly-designed rollup application that ABI-decodes the payload of its
 * advance-state input as a single dynamic `(bytes data)` value, using libcmt's
 * documented public decoder (cmt_abi_get_bytes_s + cmt_abi_get_bytes_d, exactly
 * as doc/examples/abi_decode_001.c shows), and emits `data` back as a notice.
 *
 * It rejects any input that fails to decode (accept_previous_request = false).
 * This is the whole application; it uses only the documented rollup/ABI API.
 *
 * On a correct decoder a malformed offset word is rejected, so the only outputs
 * it can ever emit are notices whose bytes came from the input payload.
 */
#include "libcmt/rollup.h"
#include "libcmt/abi.h"
#include "libcmt/buf.h"
#include <stdio.h>

int main(void) {
    cmt_rollup_t r[1];
    if (cmt_rollup_init(r)) {
        return 1;
    }
    cmt_rollup_finish_t f[1] = {{.accept_previous_request = true}};
    for (;;) {
        if (cmt_rollup_finish(r, f)) {
            return 2;
        }
        cmt_rollup_advance_t adv[1];
        if (cmt_rollup_read_advance_state(r, adv)) {
            f->accept_previous_request = false;
            continue;
        }
        /* Decode the application payload as abi `(bytes data)`. */
        cmt_buf_t frame[1];
        cmt_buf_init(frame, adv->payload.length, adv->payload.data);
        cmt_buf_t rd[1] = {*frame};
        cmt_buf_t of[1];
        cmt_abi_bytes_t data[1];
        int rc = cmt_abi_get_bytes_s(rd, of);
        if (!rc) {
            rc = cmt_abi_get_bytes_d(frame, of, &data->length, &data->data);
        }
        if (rc) {
            printf("app: payload rejected rc=%d\n", rc);
            f->accept_previous_request = false;
            continue;
        }
        printf("app: decoded %zu bytes at payload%+td\n", data->length,
            (uint8_t *) data->data - (uint8_t *) adv->payload.data);
        fflush(stdout);
        /* Commit the decoded bytes as a notice (an output in the outputs tree). */
        if (cmt_rollup_emit_notice(r, data, NULL)) {
            return 3;
        }
        f->accept_previous_request = true;
    }
}
