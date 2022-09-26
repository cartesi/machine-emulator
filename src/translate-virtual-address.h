// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//
//
// Portions of this file are adapted from Bellard,
//
// https://bellard.org/riscvemu
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

#include "compiler-defines.h"

namespace cartesi {

/// \brief Write an aligned word to memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param val Value to write.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool write_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t val) {
    auto &pma = a.template find_pma_entry<uint64_t>(paddr);
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_W())) {
        return false;
    }
    uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
    unsigned char *hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
    uint64_t hoffset = paddr - paddr_page;
    // log writes to memory
    a.write_memory_word(paddr, hpage, hoffset, val);
    // mark page as dirty so we know to update the Merkle tree
    pma.mark_dirty_page(paddr - pma.get_start());
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
    auto &pma = a.template find_pma_entry<uint64_t>(paddr);
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_R())) {
        return false;
    }
    uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
    unsigned char *hpage = a.get_host_memory(pma) + (paddr_page - pma.get_start());
    uint64_t hoffset = paddr - paddr_page;
    a.read_memory_word(paddr, hpage, hoffset, pval);
    return true;
}

namespace details {
template <uint8_t TRANSLATION_MODE, uint8_t ACCESS_TYPE>
static constexpr uint8_t to_mcause_code() {
    if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
        if constexpr (ACCESS_TYPE == ACCESS_TYPE_LOAD)
            return MCAUSE_LOAD_GUEST_PAGE_FAULT;
        else if constexpr (ACCESS_TYPE == ACCESS_TYPE_STORE)
            return MCAUSE_STORE_AMO_GUEST_PAGE_FAULT;
        else
            return MCAUSE_INSTRUCTION_GUEST_PAGE_FAULT;
    } else {
        if constexpr (ACCESS_TYPE == ACCESS_TYPE_LOAD)
            return MCAUSE_LOAD_PAGE_FAULT;
        else if constexpr (ACCESS_TYPE == ACCESS_TYPE_STORE)
            return MCAUSE_STORE_AMO_PAGE_FAULT;
        else
            return MCAUSE_FETCH_PAGE_FAULT;
    }
}

template <typename STATE_ACCESS, uint8_t TRANSLATION_MODE, uint8_t ACCESS_TYPE, bool UPDATE_PTE>
static uint8_t do_translate_virtual_address(STATE_ACCESS &a, uint64_t *ppaddr, uint64_t vaddr, int xwr_shift,
    uint8_t priv) {
    bool mxr = false;
    bool sum = false;
    uint64_t atp = 0;
    uint8_t widenbits = 0;
    if constexpr (TRANSLATION_MODE == TRANSLATION_HS) {
        mxr = a.read_mstatus() & MSTATUS_MXR_MASK;
        sum = a.read_mstatus() & MSTATUS_SUM_MASK;
        atp = a.read_satp();
    } else if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
        mxr = a.read_mstatus() & MSTATUS_MXR_MASK;
        atp = a.read_hgatp();
        widenbits = 2;
    } else { // translation == TRANSLATION_VS
        mxr = (a.read_vsstatus() & MSTATUS_MXR_MASK) || (a.read_mstatus() & MSTATUS_MXR_MASK);
        sum = a.read_vsstatus() & MSTATUS_SUM_MASK;
        atp = a.read_vsatp();
    }

    auto mode = atp >> SATP_MODE_SHIFT;
    switch (mode) {
        case SATP_MODE_BARE: // Bare: No translation or protection
            *ppaddr = vaddr;
            return 0;
        case SATP_MODE_SV39: // Sv39: Page-based 39-bit virtual addressing
        case SATP_MODE_SV48: // Sv48: Page-based 48-bit virtual addressing
        case SATP_MODE_SV57: // Sv57: Page-based 57-bit virtual addressing
            break;
        default: // Unsupported mode
            // when a guest-page-fault occurs, return the guest physical address that faulted
            if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
                *ppaddr = vaddr;
            }
            return to_mcause_code<TRANSLATION_MODE, ACCESS_TYPE>();
    }
    // Here we know we are in sv39, sv48 or sv57 modes

    // for Sv39x4 address bits 63:41 must all be zeros, or else a guest-page-fault exception occurs.
    // for Sv48x4 & Sv57x4 address bits 63:50 must all be zeros, or else a guest-page-fault exception occurs.
    if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
        uint64_t zero_bits = 0;
        if (mode == SATP_MODE_SV39) {
            zero_bits = vaddr & SV39X4_ZERO_MASK;
        } else {
            zero_bits = vaddr & SV48X4_ZERO_MASK;
        }
        if (zero_bits != 0) {
            return to_mcause_code<TRANSLATION_MODE, ACCESS_TYPE>();
        }
    }

    // Page table hierarchy of sv39 has 3 levels, sv48 has 4 levels,
    // and sv57 has 5 levels
    // ??D It doesn't seem like restricting to one or the other will
    //     simplify the code much. However, we may want to use sv39
    //     to reduce the size of the log sent to the blockchain
    int levels = static_cast<int>(mode - SATP_MODE_SV39) + 3;

    // The least significant 12 bits of vaddr are the page offset
    // Then come levels virtual page numbers (VPN)
    // The rest of vaddr must be filled with copies of the
    // most significant bit in VPN[levels] (does not apply to G translation)
    // Hence, the use of arithmetic shifts here
    int vaddr_bits = XLEN - (LOG2_PAGE_SIZE + levels * LOG2_VPN_SIZE);
    if constexpr (TRANSLATION_MODE != TRANSLATION_G) {
        if (unlikely((static_cast<int64_t>(vaddr << vaddr_bits) >> vaddr_bits) != static_cast<int64_t>(vaddr))) {
            return to_mcause_code<TRANSLATION_MODE, ACCESS_TYPE>();
        }
    }

    // Initialize pte_addr with the base address for the root page table
    uint64_t pte_addr = (atp & SATP_PPN_MASK) << LOG2_PAGE_SIZE;
    for (int i = 0; i < levels; i++) {
        int vpn_bits = LOG2_VPN_SIZE;
        if (i == 0)
            vpn_bits += widenbits;
        uint64_t vpn_mask = (1 << vpn_bits) - 1;

        // Mask out VPN[levels-i-1]
        int vaddr_shift = LOG2_PAGE_SIZE + vpn_bits * (levels - 1 - i);
        uint64_t vpn = (vaddr >> vaddr_shift) & vpn_mask;
        // Add offset to find physical address of page table entry
        pte_addr += vpn << LOG2_PTE_SIZE; //??D we can probably save this shift here
        if constexpr (TRANSLATION_MODE == TRANSLATION_VS) {
            // The spec says:
            // ```
            // When V=1, memory accesses that would normally bypass address translation are subject to G-stage address
            // translation alone.
            // ```
            // Thus, here we apply G-stage translation to the PTE address.
            uint64_t pte_addr_g = 0;
            int ret = do_translate_virtual_address<STATE_ACCESS, TRANSLATION_G, ACCESS_TYPE_LOAD, UPDATE_PTE>(a,
                &pte_addr_g, pte_addr, xwr_shift, priv);
            if (ret) {
                *ppaddr = pte_addr;
                return ret;
            }
            pte_addr = pte_addr_g;
        }
        // Read page table entry from physical memory
        uint64_t pte = 0;
        if (unlikely(!read_ram_uint64(a, pte_addr, &pte))) {
            break;
        }
        // The OS can mark page table entries as invalid,
        // but these entries shouldn't be reached during page lookups
        if (unlikely(!(pte & PTE_V_MASK))) {
            break;
        }
        // Bits 60–54 are reserved for future standard use and must be zeroed
        // by software for forward compatibility. If any of these bits are set,
        // a page-fault exception is raised.
        // Bits 62–61 are reserved for use by the Svpbmt extension and must be zeroed
        // by software for forward compatibility, or else a page-fault exception is raised.
        // If Svnapot is not implemented, bit 63 remains reserved and must be zeroed
        // by software for forward compatibility, or else a page-fault exception is raised.
        if (unlikely(pte & (PTE_60_54_MASK | PTE_PBMT_MASK | PTE_N_MASK))) {
            break;
        }
        // Clear all flags in least significant bits, then shift back to multiple of page size to form physical address.
        uint64_t ppn = (pte & PTE_PPN_MASK) << (LOG2_PAGE_SIZE - PTE_PPN_SHIFT);
        // Obtain X, W, R protection bits
        uint64_t xwr = (pte >> PTE_R_SHIFT) & (PTE_XWR_R_MASK | PTE_XWR_W_MASK | PTE_XWR_X_MASK);
        // xwr != 0 means we are done walking the page tables
        if (xwr != 0) {
            // These protection bit combinations are reserved for future use
            if (unlikely(xwr == PTE_XWR_W_MASK || xwr == (PTE_XWR_W_MASK | PTE_XWR_X_MASK))) {
                break;
            }

            // when checking the U bit for G translation, the current privilege mode is always taken to be U-mode
            if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
                if (!(pte & PTE_U_MASK)) {
                    break;
                }
            } else {
                if (priv == PRV_S) {
                    if (pte & PTE_U_MASK) {
                        // S-mode can never execute instructions from user pages, regardless of the state of SUM
                        if (unlikely(xwr_shift == PTE_XWR_X_SHIFT)) {
                            break;
                        }
                        // If SUM is not set, forbid S-mode code from accessing U-mode memory
                        if (unlikely(!sum)) {
                            break;
                        }
                    }
                } else {
                    // Forbid U-mode code from accessing S-mode memory
                    if (unlikely(!(pte & PTE_U_MASK))) {
                        break;
                    }
                }
            }

            // MXR allows read access to execute-only pages
            if (mxr) {
                // Set R bit if X bit is set
                xwr |= (xwr >> PTE_XWR_X_SHIFT);
            }

            // Check protection bits against requested access
            if (unlikely(((xwr >> xwr_shift) & 1) == 0)) {
                break;
            }
            // Check page, megapage, and gigapage alignment
            uint64_t vaddr_mask = (UINT64_C(1) << vaddr_shift) - 1;
            if (unlikely(ppn & vaddr_mask)) {
                break;
            }
            // Decide if we need to update access bits in pte
            if constexpr (UPDATE_PTE) {
                uint64_t update_pte = pte;
                update_pte |= PTE_A_MASK; // Set access bit
                if (xwr_shift == PTE_XWR_W_SHIFT) {
                    update_pte |= PTE_D_MASK; // Set dirty bit
                }
                if (pte != update_pte) {
                    write_ram_uint64<STATE_ACCESS>(a, pte_addr, update_pte); // Can't fail since read succeeded earlier
                }
            }
            // Add page offset in vaddr to ppn to form physical address
            *ppaddr = (vaddr & vaddr_mask) | (ppn & ~vaddr_mask);
            return 0;
            // xwr == 0 means we have a pointer to the start of the next page table
        } else {
            pte_addr = ppn;
        }
    }

    // when a guest-page-fault occurs, return the guest physical address that faulted
    if constexpr (TRANSLATION_MODE == TRANSLATION_G) {
        *ppaddr = vaddr;
    }
    return to_mcause_code<TRANSLATION_MODE, ACCESS_TYPE>();
}
} // namespace details

/// \brief Walk the page table and translate a virtual address to the corresponding physical address
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \tparam ACCESS_TYPE memory access type (fetch, store or load).
/// \param a Machine state accessor object.
/// \param ppaddr Pointer to physical address.
/// \param vaddr Virtual address
/// \param access_mode Encoded mode (virtual/non-virtual) and privilege of the memory access.
/// \param xwr_shift Encodes the access mode by the shift to the XWR triad (PTE_XWR_R_SHIFT,
///  PTE_XWR_W_SHIFT, or PTE_XWR_X_SHIFT)
/// \returns 0 if succeeded, the corresponding MCAUSE code otherwise. Please note that 0 is
/// repurposed here to be equivalent as success because the function will never return misaligned causes.
template <typename STATE_ACCESS, uint8_t ACCESS_TYPE, bool UPDATE_PTE = true>
static uint8_t translate_virtual_address(STATE_ACCESS &a, uint64_t *ppaddr, uint64_t vaddr, MODE_constants access_mode,
    int xwr_shift) {
    uint8_t priv = (access_mode & ACCESS_MODE_PRV_MASK) >> ACCESS_MODE_PRV_SHIFT;
    uint8_t virt = (access_mode & ACCESS_MODE_VRT_MASK) >> ACCESS_MODE_VRT_SHIFT;

    // M-mode code does not use virtual memory
    if (unlikely(priv == PRV_M)) {
        *ppaddr = vaddr;
        return 0;
    }

    if (unlikely(virt)) {
        uint64_t guest_paddr = 0;
        int ret = details::do_translate_virtual_address<STATE_ACCESS, TRANSLATION_VS, ACCESS_TYPE, UPDATE_PTE>(a,
            &guest_paddr, vaddr, xwr_shift, priv);
        if (unlikely(ret)) {
            return ret;
        }
        // for G-stage translation guest-page-fault exceptions are raised instead of regular page-fault exceptions
        return details::do_translate_virtual_address<STATE_ACCESS, TRANSLATION_G, ACCESS_TYPE, UPDATE_PTE>(a, ppaddr,
            guest_paddr, xwr_shift, priv);
    } else {
        return details::do_translate_virtual_address<STATE_ACCESS, TRANSLATION_HS, ACCESS_TYPE, UPDATE_PTE>(a, ppaddr,
            vaddr, xwr_shift, priv);
    }
}
} // namespace cartesi

#endif /* end of include guard: TRANSLATE_VIRTUAL_ADDRESS_H */
