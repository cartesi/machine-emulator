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

// Portions of this file are adapted from Bellard,
//
// https://bellard.org/tinyemu/
//
// released under the MIT license:
//
// Copyright (c) 2016-2017 Fabrice Bellard
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef TRANSLATE_VIRTUAL_ADDRESS_H
#define TRANSLATE_VIRTUAL_ADDRESS_H

#include <cstdint>

#include "compiler-defines.h"
#include "find-pma-entry.h"
#include "riscv-constants.h"

namespace cartesi {

/// \brief Write an aligned word to memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param val Value to write.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool write_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t val) {
    uint64_t pma_index = 0;
    auto &pma = find_pma_entry<uint64_t>(a, paddr, pma_index);
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_W())) {
        return false;
    }
    const auto faddr = a.get_faddr(paddr, pma_index);
    // log writes to memory
    a.write_memory_word(faddr, pma_index, val);
    // mark page as dirty so we know to update the Merkle tree
    a.mark_dirty_page(faddr, pma_index);
    return true;
}

/// \brief Read an aligned word from memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param pval Pointer to word.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool read_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t *pval) {
    uint64_t pma_index = 0;
    auto &pma = find_pma_entry<uint64_t>(a, paddr, pma_index);
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_R())) {
        return false;
    }
    const auto faddr = a.get_faddr(paddr, pma_index);
    a.read_memory_word(faddr, pma_index, pval);
    return true;
}

/// \brief Walk the page table and translate a virtual address to the corresponding physical address
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \tparam UPDATE_PTE Whether PTE entries can be modified during the translation.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address
/// \param ppaddr Pointer to physical address.
/// \param xwr_shift Encodes the access mode by the shift to the XWR triad (PTE_XWR_R_SHIFT,
///  PTE_XWR_R_SHIFT, or PTE_XWR_R_SHIFT)
/// \details This function is outlined to minimize host CPU code cache pressure.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS, bool UPDATE_PTE = true>
static NO_INLINE bool translate_virtual_address(STATE_ACCESS &a, uint64_t *ppaddr, uint64_t vaddr, int xwr_shift) {
    auto prv = a.read_iprv();
    const uint64_t mstatus = a.read_mstatus();

    // When MPRV is set, data loads and stores use privilege in MPP
    // instead of the current privilege level (code access is unaffected)
    if (xwr_shift != PTE_XWR_X_SHIFT && (mstatus & MSTATUS_MPRV_MASK)) {
        prv = (mstatus & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT;
    }

    // The satp register is considered active when the effective privilege mode is S-mode or U-mode.
    // Executions of the address-translation algorithm may only begin using a given value of satp when
    // satp is active.
    if (unlikely(prv > PRV_S)) {
        // We are in M-mode (or in HS-mode if Hypervisor extension is active)
        *ppaddr = vaddr;
        return true;
    }

    const uint64_t satp = a.read_satp();

    const uint64_t mode = satp >> SATP_MODE_SHIFT;
    switch (mode) {
        case SATP_MODE_BARE: // Bare: No translation or protection
            *ppaddr = vaddr;
            return true;
        case SATP_MODE_SV39: // Sv39: Page-based 39-bit virtual addressing
        case SATP_MODE_SV48: // Sv48: Page-based 48-bit virtual addressing
#ifndef NO_SATP_MODE_SV57
        case SATP_MODE_SV57: // Sv57: Page-based 57-bit virtual addressing
#endif
            break;
        default: // Unsupported mode
            return false;
    }
    // Here we know we are in sv39, sv48 or sv57 modes

    // Page table hierarchy of sv39 has 3 levels, sv48 has 4 levels,
    // and sv57 has 5 levels
    // ??D It doesn't seem like restricting to one or the other will
    //     simplify the code much. However, we may want to use sv39
    //     to reduce the size of the log sent to the blockchain
    const int levels = static_cast<int>(mode - SATP_MODE_SV39) + 3;

    // The least significant 12 bits of vaddr are the page offset
    // Then come levels virtual page numbers (VPN)
    // The rest of vaddr must be filled with copies of the
    // most significant bit in VPN[levels]
    // Hence, the use of arithmetic shifts here
    const int vaddr_bits = XLEN - (LOG2_PAGE_SIZE + levels * LOG2_VPN_SIZE);
    if (unlikely((static_cast<int64_t>(vaddr << vaddr_bits) >> vaddr_bits) != static_cast<int64_t>(vaddr))) {
        return false;
    }

    // Initialize pte_addr with the base address for the root page table
    uint64_t pte_addr = (satp & SATP_PPN_MASK) << LOG2_PAGE_SIZE;
    for (int i = 0; i < levels; i++) {
        // Mask out VPN[levels-i-1]
        const int vaddr_shift = LOG2_PAGE_SIZE + LOG2_VPN_SIZE * (levels - 1 - i);
        const uint64_t vpn = (vaddr >> vaddr_shift) & VPN_MASK;
        // Add offset to find physical address of page table entry
        pte_addr += vpn << LOG2_PTE_SIZE; //??D we can probably save this shift here
        // Read page table entry from physical memory
        uint64_t pte = 0;
        if (unlikely(!read_ram_uint64(a, pte_addr, &pte))) {
            return false;
        }
        // The OS can mark page table entries as invalid,
        // but these entries shouldn't be reached during page lookups
        if (unlikely(!(pte & PTE_V_MASK))) {
            return false;
        }
        // Bits 60–54 are reserved for future standard use and must be zeroed
        // by software for forward compatibility. If any of these bits are set,
        // a page-fault exception is raised.
        // Bits 62–61 are reserved for use by the Svpbmt extension and must be zeroed
        // by software for forward compatibility, or else a page-fault exception is raised.
        // If Svnapot is not implemented, bit 63 remains reserved and must be zeroed
        // by software for forward compatibility, or else a page-fault exception is raised.
        if (unlikely(pte & (PTE_60_54_MASK | PTE_PBMT_MASK | PTE_N_MASK))) {
            return false;
        }
        // Clear all flags in least significant bits, then shift back to multiple of page size to form physical address.
        const uint64_t ppn = (pte & PTE_PPN_MASK)
            << (static_cast<int>(LOG2_PAGE_SIZE) - static_cast<int>(PTE_PPN_SHIFT));
        // Obtain X, W, R protection bits
        uint64_t xwr = (pte >> PTE_R_SHIFT) & (PTE_XWR_R_MASK | PTE_XWR_W_MASK | PTE_XWR_X_MASK);
        // xwr != 0 means we are done walking the page tables
        if (xwr != 0) {
            // These protection bit combinations are reserved for future use
            if (unlikely(xwr == PTE_XWR_W_MASK || xwr == (PTE_XWR_W_MASK | PTE_XWR_X_MASK))) {
                return false;
            }
            // (We know we are not PRV_M if we reached here)
            if (prv == PRV_S) {
                if ((pte & PTE_U_MASK)) {
                    // S-mode can never execute instructions from user pages, regardless of the state of SUM
                    if (unlikely(xwr_shift == PTE_XWR_X_SHIFT)) {
                        return false;
                    }
                    // If SUM is not set, forbid S-mode code from accessing U-mode memory
                    if (unlikely(!(mstatus & MSTATUS_SUM_MASK))) {
                        return false;
                    }
                }
            } else {
                // Forbid U-mode code from accessing S-mode memory
                if (unlikely(!(pte & PTE_U_MASK))) {
                    return false;
                }
            }
            // MXR allows read access to execute-only pages
            if (mstatus & MSTATUS_MXR_MASK) {
                // Set R bit if X bit is set
                xwr |= (xwr >> PTE_XWR_X_SHIFT);
            }
            // Check protection bits against requested access
            if (unlikely(((xwr >> xwr_shift) & 1) == 0)) {
                return false;
            }
            // Check page, megapage, and gigapage alignment
            const uint64_t vaddr_mask = (UINT64_C(1) << vaddr_shift) - 1;
            if (unlikely(ppn & vaddr_mask)) {
                return false;
            }
            // Decide if we need to update access bits in pte
            if constexpr (UPDATE_PTE) {
                uint64_t update_pte = pte;
                update_pte |= PTE_A_MASK; // Set access bit
                if (xwr_shift == PTE_XWR_W_SHIFT) {
                    update_pte |= PTE_D_MASK; // Set dirty bit
                }
                if (pte != update_pte) {
                    write_ram_uint64(a, pte_addr, update_pte); // Can't fail since read succeeded earlier
                }
            }
            // Add page offset in vaddr to ppn to form physical address
            *ppaddr = (vaddr & vaddr_mask) | (ppn & ~vaddr_mask);
            return true;
            // xwr == 0 means we have a pointer to the start of the next page table
        }
        pte_addr = ppn;
    }
    return false;
}

} // namespace cartesi

#endif /* end of include guard: TRANSLATE_VIRTUAL_ADDRESS_H */
