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

namespace cartesi {

/// \brief Write an aligned word to memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param val Value to write.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool write_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t val) {
    pma_entry &pma = a.template find_pma_entry<uint64_t>(paddr);
    if (!pma.get_istart_M() || !pma.get_istart_W()) {
        return false;
    }
    uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
    unsigned char *hpage = pma.get_memory().get_host_memory() + (paddr_page - pma.get_start());
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
    pma_entry &pma = a.template find_pma_entry<uint64_t>(paddr);
    if (!pma.get_istart_M() || !pma.get_istart_R()) {
        return false;
    }
    uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
    unsigned char *hpage = pma.get_memory().get_host_memory() + (paddr_page - pma.get_start());
    uint64_t hoffset = paddr - paddr_page;
    a.read_memory_word(paddr, hpage, hoffset, pval);
    return true;
}

/// \brief Walk the page table and translate a virtual address to the corresponding physical address
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address
/// \param ppaddr Pointer to physical address.
/// \param xwr_shift Encodes the access mode by the shift to the XWR triad (PTE_XWR_R_SHIFT,
///  PTE_XWR_R_SHIFT, or PTE_XWR_R_SHIFT)
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static bool translate_virtual_address(STATE_ACCESS &a, uint64_t *ppaddr, uint64_t vaddr, int xwr_shift) {
    auto note = a.make_scoped_note("translate_virtual_address");
    (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();

    // When MPRV is set, data loads and stores use privilege in MPP
    // instead of the current privilege level (code access is unaffected)
    if ((mstatus & MSTATUS_MPRV_MASK) && xwr_shift != PTE_XWR_C_SHIFT) {
        priv = (mstatus & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT;
    }

    // The satp register is considered active when the effective privilege mode is S-mode or U-mode.
    // Executions of the address-translation algorithm may only begin using a given value of satp when
    // satp is active.
    if (priv > PRV_S) {
        // We are in M-mode (or in HS-mode if Hypervisor extension is active)
        *ppaddr = vaddr;
        return true;
    }

    uint64_t satp = a.read_satp();

    // In RV64, mode can be
    //   0: Bare: No translation or protection
    //   8: sv39: Page-based 39-bit virtual addressing
    //   9: sv48: Page-based 48-bit virtual addressing
    //   10: sv57: Page-based 57-bit virtual addressing
    auto mode = static_cast<int>(satp >> 60) & 0xf;
    if (mode == 0) {
        *ppaddr = vaddr;
        return true;
    } else if (mode < 8 || mode > 10) {
        return false;
    }
    // Here we know we are in sv39, sv48 or sv57 modes

    // Page table hierarchy of sv39 has 3 levels, sv48 has 4 levels,
    // and sv57 has 5 levels
    // ??D It doesn't seem like restricting to one or the other will
    //     simplify the code much. However, we may want to use sv39
    //     to reduce the size of the log sent to the blockchain
    int levels = mode - 8 + 3;

    // The least significant 12 bits of vaddr are the page offset
    // Then come levels virtual page numbers (VPN)
    // The rest of vaddr must be filled with copies of the
    // most significant bit in VPN[levels]
    // Hence, the use of arithmetic shifts here
    int vaddr_shift = XLEN - (PAGE_NUMBER_SHIFT + levels * 9);
    if (((static_cast<int64_t>(vaddr) << vaddr_shift) >> vaddr_shift) != static_cast<int64_t>(vaddr)) {
        return false;
    }

    // The least significant 44 bits of satp contain the physical page number for the root page table
    const int satp_ppn_bits = 44;
    // Initialize pte_addr with the base address for the root page table
    uint64_t pte_addr = (satp & ((UINT64_C(1) << satp_ppn_bits) - 1)) << PAGE_NUMBER_SHIFT;
    // All page table entries have 8 bytes
    const int log2_pte_size = 3;
    // Each page table has 4k/pte_size entries
    // To index all entries, we need vpn_bits
    const int vpn_bits = 12 - log2_pte_size;
    uint64_t vpn_mask = (1 << vpn_bits) - 1;
    for (int i = 0; i < levels; i++) {
        // Mask out VPN[levels-i-1]
        vaddr_shift = PAGE_NUMBER_SHIFT + vpn_bits * (levels - 1 - i);
        uint64_t vpn = (vaddr >> vaddr_shift) & vpn_mask;
        // Add offset to find physical address of page table entry
        pte_addr += vpn << log2_pte_size; //??D we can probably save this shift here
        // Read page table entry from physical memory
        uint64_t pte = 0;
        if (!read_ram_uint64(a, pte_addr, &pte)) {
            return false;
        }
        // The OS can mark page table entries as invalid,
        // but these entries shouldn't be reached during page lookups
        if (!(pte & PTE_V_MASK)) {
            return false;
        }
        // Bits 60–54 are reserved for future standard use and must be zeroed
        // by software for forward compatibility. If any of these bits are set,
        // a page-fault exception is raised.
        if (pte & PTE_60_54_MASK) {
            return false;
        }
        // Clear all flags in least significant bits, then shift back to multiple of page size to form physical address
        uint64_t ppn = (pte >> 10) << PAGE_NUMBER_SHIFT;
        // Obtain X, W, R protection bits
        auto xwr = (pte >> 1) & 7;
        // xwr != 0 means we are done walking the page tables
        if (xwr != 0) {
            // These protection bit combinations are reserved for future use
            if (xwr == 2 || xwr == 6) {
                return false;
            }
            // (We know we are not PRV_M if we reached here)
            if (priv == PRV_S) {
                if ((pte & PTE_U_MASK)) {
                    // S-mode can never execute instructions from user pages, regardless of the state of SUM
                    if (xwr_shift == PTE_XWR_C_SHIFT) {
                        return false;
                    }
                    // If SUM is not set, forbid S-mode code from accessing U-mode memory
                    if (!(mstatus & MSTATUS_SUM_MASK)) {
                        return false;
                    }
                }
            } else {
                // Forbid U-mode code from accessing S-mode memory
                if (!(pte & PTE_U_MASK)) {
                    return false;
                }
            }
            // MXR allows read access to execute-only pages
            if (mstatus & MSTATUS_MXR_MASK) {
                // Set R bit if X bit is set
                xwr |= (xwr >> 2);
            }
            // Check protection bits against requested access
            if (((xwr >> xwr_shift) & 1) == 0) {
                return false;
            }
            // Check page, megapage, and gigapage alignment
            uint64_t vaddr_mask = (UINT64_C(1) << vaddr_shift) - 1;
            if (ppn & vaddr_mask) {
                return false;
            }
            // Decide if we need to update access bits in pte
            bool update_pte = !(pte & PTE_A_MASK) || (!(pte & PTE_D_MASK) && xwr_shift == PTE_XWR_W_SHIFT);
            pte |= PTE_A_MASK;
            if (xwr_shift == PTE_XWR_W_SHIFT) {
                pte |= PTE_D_MASK;
            }
            // If so, update pte
            if (update_pte) {
                write_ram_uint64(a, pte_addr, pte); // Can't fail since read succeeded earlier
            }
            // Add page offset in vaddr to ppn to form physical address
            *ppaddr = (vaddr & vaddr_mask) | (ppn & ~vaddr_mask);
            return true;
            // xwr == 0 means we have a pointer to the start of the next page table
        } else {
            // For non-leaf PTEs, bits 62–61 are reserved for future standard use.
            // Until their use is defined by a standard extension, they must be cleared by
            // software for forward compatibility, or else a page-fault exception is raised.
            if (pte & PTE_PBMT_MASK) {
                return false;
            }
            pte_addr = ppn;
        }
    }
    return false;
}

} // namespace cartesi

#endif /* end of include guard: TRANSLATE_VIRTUAL_ADDRESS_H */
