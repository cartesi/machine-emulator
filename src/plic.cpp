// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#include "plic.h"
#include "i-device-state-access.h"
#include "pma-constants.h"
#include "riscv-constants.h"

#include <cassert>
#include <cstdio>

// Enable these defines to debug PLIC
// #define DEBUG_PLIC
// #define DEBUG_PLIC_MMIO

namespace cartesi {

// The return value is undefined if v == 0
// This works on gcc and clang and uses the lzcnt instruction
static inline uint32_t ilog2(uint32_t v) {
    return 31 - __builtin_clz(v);
}

/// \brief Called only bu the driver when it wants retrieve current pending interrupt requests.
static uint32_t plic_read_pending(i_device_state_access *a) {
    // The actual pending interrupt sources are masked by interrupts being served
    const uint32_t girqpend = a->read_plic_girqpend();
    const uint32_t girqsrvd = a->read_plic_girqsrvd();
    const uint32_t ipmask = girqpend & ~girqsrvd;
#ifdef DEBUG_PLIC
    (void) fprintf(stderr, "plic: read pending ipmask=%d\n", ipmask);
#endif
    return ipmask;
}

/// \brief Called only by the driver when it begins serving a pending interrupt request.
static bool plic_read_claim_complete(i_device_state_access *a, uint64_t *val) {
    const uint32_t girqpend = a->read_plic_girqpend();
    uint32_t girqsrvd = a->read_plic_girqsrvd();
    uint32_t ipmask = girqpend & ~girqsrvd;
    // Are there pending interrupts that have yet to be served?
    if (ipmask != 0) {
        // On receiving a claim message,
        // the PLIC will atomically determine the interrupt source id
        // of the highest-priority pending interrupt for the target
        // and then clear down the corresponding source's IP bit.
        // We actually clear the source IP bit by masking girqsrvd until its claim is complete.
        const uint32_t irq_id = ilog2(ipmask);
        const uint32_t irq_mask = UINT32_C(1) << irq_id;
        girqsrvd |= irq_mask;
        a->write_plic_girqsrvd(girqsrvd);
        // The PLIC will then return the interrupt source id to the target
        *val = irq_id;
        // If all pending interrupts have been served, reset mip.
        ipmask = girqpend & ~girqsrvd;
        if (ipmask == 0) {
            a->reset_mip(MIP_MEIP_MASK | MIP_SEIP_MASK);
        }
    } else {
        // The PLIC will return an id of zero, if there were no pending interrupts for the target
        *val = 0;
    }
#ifdef DEBUG_PLIC
    (void) fprintf(stderr, "plic: claim irq_id=%d\n", (int) *val);
#endif
    return true;
}

/// \brief Called only by the driver when it completes serving a pending interrupt request.
static execute_status plic_write_claim_complete(i_device_state_access *a, uint32_t val) {
#ifdef DEBUG_PLIC
    (void) fprintf(stderr, "plic: claim complete irq_id=%d\n", val);
#endif
    if (val >= 1 && val <= PMA_PLIC_MAX_IRQ_DEF) {
        // On completing, we need to clear its corresponding girqsrvd mask
        const uint32_t girqpend = a->read_plic_girqpend();
        uint32_t girqsrvd = a->read_plic_girqsrvd();
        const uint32_t irq_mask = UINT32_C(1) << val;
        girqsrvd &= ~irq_mask;
        a->write_plic_girqsrvd(girqsrvd);
        // If all pending interrupts have been served, reset mip. Otherwise, set mip.
        const uint32_t ipmask = girqpend & ~girqsrvd;
        if (ipmask == 0) {
            a->reset_mip(MIP_MEIP_MASK | MIP_SEIP_MASK);
        } else {
            a->set_mip(MIP_MEIP_MASK | MIP_SEIP_MASK);
            return execute_status::success_and_serve_interrupts;
        }
    }
    return execute_status::success;
}

/// \brief PLIC device read callback. See ::pma_read.
static bool plic_read(void *context, i_device_state_access *a, uint64_t offset, uint64_t *val, int log2_size) {
    (void) context;
#ifdef DEBUG_PLIC_MMIO
    (void) fprintf(stderr, "plic: mmio read offset=0x%lx log2_size=%d\n", (long) offset, log2_size);
#endif

    // Our PLIC only supports aligned 32-bit reads
    if (offset & 3 || log2_size != 2 || offset > PMA_PLIC_LENGTH) {
        return false;
    }

    switch (offset) {
        case plic_csr_rel_addr::priority1:
        case plic_csr_rel_addr::priority2:
        case plic_csr_rel_addr::priority3:
        case plic_csr_rel_addr::priority4:
        case plic_csr_rel_addr::priority5:
        case plic_csr_rel_addr::priority6:
        case plic_csr_rel_addr::priority7:
        case plic_csr_rel_addr::priority8:
        case plic_csr_rel_addr::priority9:
        case plic_csr_rel_addr::priority10:
        case plic_csr_rel_addr::priority11:
        case plic_csr_rel_addr::priority12:
        case plic_csr_rel_addr::priority13:
        case plic_csr_rel_addr::priority14:
        case plic_csr_rel_addr::priority15:
        case plic_csr_rel_addr::priority16:
        case plic_csr_rel_addr::priority17:
        case plic_csr_rel_addr::priority18:
        case plic_csr_rel_addr::priority19:
        case plic_csr_rel_addr::priority20:
        case plic_csr_rel_addr::priority21:
        case plic_csr_rel_addr::priority22:
        case plic_csr_rel_addr::priority23:
        case plic_csr_rel_addr::priority24:
        case plic_csr_rel_addr::priority25:
        case plic_csr_rel_addr::priority26:
        case plic_csr_rel_addr::priority27:
        case plic_csr_rel_addr::priority28:
        case plic_csr_rel_addr::priority29:
        case plic_csr_rel_addr::priority30:
        case plic_csr_rel_addr::priority31:
            // A valid implementation can hardwire all input priority levels.
            // We hardwire all supported interrupt sources to the lowest priority
            *val = PLIC_LOWEST_IRQ_PRIORITY;
            return true;
        case plic_csr_rel_addr::pending:
            *val = plic_read_pending(a);
            return true;
        case plic_csr_rel_addr::enabled:
            // A valid implementation can hardwire interrupt routing to a fixed hart context.
            // We hardwire all supported interrupt source to be always enabled in context 0.
            *val = PLIC_ENABLED_IRQ_MASK;
            return true;
        case plic_csr_rel_addr::claim_complete:
            return plic_read_claim_complete(a, val);
        default:
            // Other PLIC CSRs are WARL hardwired to 0
            *val = 0;
            return true;
    }
}

/// \brief PLIC device read callback. See ::pma_write.
static execute_status plic_write(void *context, i_device_state_access *a, uint64_t offset, uint64_t val,
    int log2_size) {
    (void) context;
#ifdef DEBUG_PLIC_MMIO
    (void) fprintf(stderr, "plic: mmio write offset=0x%lx log2_size=%d val=0x%x\n", (long) offset, log2_size,
        (int) val);
#endif

    // Our PLIC only supports aligned 32-bit reads
    if (offset & 3 || log2_size != 2 || offset > PMA_PLIC_LENGTH) {
        return execute_status::failure;
    }

    switch (offset) {
        case plic_csr_rel_addr::claim_complete:
            return plic_write_claim_complete(a, val);
        default:
            // Most CSRs in PLIC spec are WARL,
            // therefore we just ignore writes
            return execute_status::success;
    }
}

void plic_set_pending_irq(i_device_state_access *a, uint32_t irq_id) {
    const uint32_t irq_mask = UINT32_C(1) << irq_id;
    const uint32_t girqsrvd = a->read_plic_girqsrvd();
    uint32_t girqpend = a->read_plic_girqpend();
    girqpend |= irq_mask;
    a->write_plic_girqpend(girqpend);
    // Set mip only if we the pending interrupt is not already being served.
    // In case it's being served, mip will be set just after next claim complete.
    const uint32_t ipmask = girqpend & ~girqsrvd;
    if (ipmask != 0) {
        a->set_mip(MIP_MEIP_MASK | MIP_SEIP_MASK);
    }
}

void plic_reset_pending_irq(i_device_state_access *a, uint32_t irq_id) {
    const uint32_t irq_mask = UINT32_C(1) << irq_id;
    const uint32_t girqsrvd = a->read_plic_girqsrvd();
    uint32_t girqpend = a->read_plic_girqpend();
    girqpend &= ~irq_mask;
    a->write_plic_girqpend(girqpend);
    // If all pending interrupts have been served, reset mip.
    const uint32_t ipmask = girqpend & ~girqsrvd;
    if (ipmask == 0) {
        a->reset_mip(MIP_MEIP_MASK | MIP_SEIP_MASK);
    }
}

const pma_driver plic_driver = {"PLIC", plic_read, plic_write};

} // namespace cartesi
