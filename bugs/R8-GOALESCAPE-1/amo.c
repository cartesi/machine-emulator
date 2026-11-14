/* AMO atomicity / translation probe for R8-GOALESCAPE-1.
 *
 * Scenario A: split read/write translation (stale TLB) -> one AMO loads from P1 and stores to P2.
 * Scenario C: AMO on its own (self-mapping) PTE with A=0, D=0 -> the stored write-back clears D.
 * Control  : a normal AMO with a consistent (never-remapped) translation, which must be atomic.
 *
 * All scenarios run in S-mode under Sv39 paging. Results are written to a fixed physical address so the
 * Lua driver reads them deterministically. HTIF is mapped so the guest can halt directly from S-mode.
 */
#include <cm-baremetal.h>
#include <stdint.h>
#define PT_BASE 0x80800000UL
#define P1 0x80910000UL
#define P2 0x80911000UL
#define PC 0x80914000UL /* control page (consistent translation) */
#define RESULT ((volatile uint64_t *) 0x80920000UL)
#define csrw(r, v) asm volatile("csrw " #r ", %0" ::"r"((uint64_t) (v)))
#define csrr(r) ({ uint64_t __v; asm volatile("csrr %0, " #r : "=r"(__v)); __v; })
static volatile uint64_t *const root = (uint64_t *) (PT_BASE);
static volatile uint64_t *const t1 = (uint64_t *) (PT_BASE + 0x1000);
static volatile uint64_t *const t0 = (uint64_t *) (PT_BASE + 0x2000);
static inline uint64_t pte(uint64_t pa, uint64_t f) { return ((pa >> 12) << 10) | f; }

void s_code(void) {
    volatile uint64_t *v = (volatile uint64_t *) 0x1000a000UL;
    uint64_t x = *v;                 /* read TLB: V -> P1 (value 100) */
    t0[10] = pte(P2, 0xc7);          /* remap V -> P2, no sfence.vma */
    *(v + 1) = 0x77;                 /* store: write-TLB miss refills V -> P2 (writes P2+8) */
    uint64_t old;
    asm volatile("amoadd.d %0, %1, (%2)" : "=r"(old) : "r"(1UL), "r"(v) : "memory");
    RESULT[0] = old;
    RESULT[1] = *(volatile uint64_t *) P1;   /* identity-mapped gigapage in S-mode */
    RESULT[2] = *(volatile uint64_t *) P2;
    RESULT[5] = x;

    /* scenario C: AMO on its own PTE (V|R|W, A=0, D=0) */
    volatile uint64_t *self = (volatile uint64_t *) (0x1000b000UL + 11 * 8);
    uint64_t oldc;
    asm volatile("amoor.d %0, %1, (%2)" : "=r"(oldc) : "r"(0UL), "r"(self) : "memory");
    RESULT[3] = t0[11];
    RESULT[4] = oldc;

    /* control: a normal AMO with a consistent (never-remapped) translation must be atomic */
    volatile uint64_t *vc = (volatile uint64_t *) 0x1000e000UL; /* -> PC via t0[14] */
    uint64_t oldk;
    asm volatile("amoadd.d %0, %1, (%2)" : "=r"(oldk) : "r"(1UL), "r"(vc) : "memory");
    RESULT[7] = oldk;
    RESULT[8] = *(volatile uint64_t *) PC;

    cm_halt(0); /* HTIF mapped (root[1]); halt directly from S-mode */
}

int main(void) {
    for (int i = 0; i < 3 * 512; i++) root[i] = 0;
    root[2] = pte(0x80000000UL, 0xcf); /* identity gigapage 0x80000000-0xBFFFFFFF, RWX A D V */
    root[1] = pte(0x40000000UL, 0xc7); /* identity gigapage 0x40000000-0x7FFFFFFF, RW A D V (HTIF) */
    root[0] = pte((uint64_t) t1, 1);
    t1[0x80] = pte((uint64_t) t0, 1);
    t0[10] = pte(P1, 0xc7);            /* V -> P1 initially */
    t0[11] = pte((uint64_t) t0, 0x07); /* self-map, A=0, D=0 */
    t0[14] = pte(PC, 0xc7);            /* control: Vc -> PC, V|R|W|A|D */
    *(volatile uint64_t *) P1 = 100;
    *(volatile uint64_t *) P2 = 200;
    *(volatile uint64_t *) PC = 300;
    for (int i = 0; i < 9; i++) RESULT[i] = 0;
    csrw(satp, (8UL << 60) | (PT_BASE >> 12));
    asm volatile("sfence.vma");
    uint64_t ms = csrr(mstatus);
    ms = (ms & ~(3UL << 11)) | (1UL << 11); /* MPP = S */
    csrw(mstatus, ms);
    csrw(mepc, (uint64_t) s_code);
    asm volatile("mret");
    return 1;
}
