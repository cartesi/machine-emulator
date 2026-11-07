/* R5-DFINPUT-1 proof-of-concept guest application: a one-question ballot box.
 *
 * A correctly designed rollup application that decodes the payload of each
 * advance-state input as abi `(bool yes)` with libcmt's documented public
 * decoder cmt_abi_get_bool (include/libcmt/abi.h), rejects the input when the
 * decoder reports an error, and otherwise counts the ballot and emits a notice
 * with the per-ballot and running tallies. It uses only the documented
 * rollup/ABI API. For every input the ABI defines as a valid bool, a ballot adds
 * exactly one vote (yes or no).
 */
#include "libcmt/abi.h"
#include "libcmt/buf.h"
#include "libcmt/rollup.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static unsigned total_yes, total_no;

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
        cmt_buf_t rd[1];
        cmt_buf_init(rd, adv->payload.length, adv->payload.data);
        bool yes = false;
        int rc = cmt_abi_get_bool(rd, &yes);
        if (rc) {
            printf("app: ballot rejected rc=%d\n", rc);
            fflush(stdout);
            f->accept_previous_request = false;
            continue;
        }
        unsigned ballot_yes = yes;  /* one vote for yes ... */
        unsigned ballot_no = !yes;  /* ... or one vote for no */
        total_yes += ballot_yes;
        total_no += ballot_no;
        char msg[128];
        int n = snprintf(msg, sizeof(msg), "ballot yes=%u no=%u total yes=%u no=%u", ballot_yes, ballot_no,
            total_yes, total_no);
        printf("app: %s\n", msg);
        fflush(stdout);
        cmt_abi_bytes_t notice = {.length = (size_t) n, .data = msg};
        if (cmt_rollup_emit_notice(r, &notice, NULL)) {
            return 3;
        }
        f->accept_previous_request = true;
    }
}
