/*
 * Dummy VGA device
 * 
 * Copyright (c) 2003-2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "cutils.h"
#include "iomem.h"
#include "virtio.h"
#include "machine.h"

//#define DEBUG_VBE

#define MSR_COLOR_EMULATION 0x01
#define MSR_PAGE_SELECT     0x20

#define ST01_V_RETRACE      0x08
#define ST01_DISP_ENABLE    0x01

#define VBE_DISPI_INDEX_ID              0x0
#define VBE_DISPI_INDEX_XRES            0x1
#define VBE_DISPI_INDEX_YRES            0x2
#define VBE_DISPI_INDEX_BPP             0x3
#define VBE_DISPI_INDEX_ENABLE          0x4
#define VBE_DISPI_INDEX_BANK            0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH      0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT     0x7
#define VBE_DISPI_INDEX_X_OFFSET        0x8
#define VBE_DISPI_INDEX_Y_OFFSET        0x9
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 0xa
#define VBE_DISPI_INDEX_NB              0xb

#define VBE_DISPI_ID0                   0xB0C0
#define VBE_DISPI_ID1                   0xB0C1
#define VBE_DISPI_ID2                   0xB0C2
#define VBE_DISPI_ID3                   0xB0C3
#define VBE_DISPI_ID4                   0xB0C4
#define VBE_DISPI_ID5                   0xB0C5

#define VBE_DISPI_DISABLED              0x00
#define VBE_DISPI_ENABLED               0x01
#define VBE_DISPI_GETCAPS               0x02
#define VBE_DISPI_8BIT_DAC              0x20
#define VBE_DISPI_LFB_ENABLED           0x40
#define VBE_DISPI_NOCLEARMEM            0x80

#define FB_ALLOC_ALIGN (1 << 20)

#define MAX_TEXT_WIDTH 132
#define MAX_TEXT_HEIGHT 60

struct VGAState {
    FBDevice *fb_dev;
    int fb_page_count;
    PhysMemoryRange *mem_range;
    PhysMemoryRange *mem_range2;
    PCIDevice *pci_dev;
    PhysMemoryRange *rom_range;

    uint8_t *vga_ram; /* 128K at 0xa0000 */
    
    uint8_t sr_index;
    uint8_t sr[8];
    uint8_t gr_index;
    uint8_t gr[16];
    uint8_t ar_index;
    uint8_t ar[21];
    int ar_flip_flop;
    uint8_t cr_index;
    uint8_t cr[256]; /* CRT registers */
    uint8_t msr; /* Misc Output Register */
    uint8_t fcr; /* Feature Control Register */
    uint8_t st00; /* status 0 */
    uint8_t st01; /* status 1 */
    uint8_t dac_state;
    uint8_t dac_sub_index;
    uint8_t dac_read_index;
    uint8_t dac_write_index;
    uint8_t dac_cache[3]; /* used when writing */
    uint8_t palette[768];
    
    /* text mode state */
    uint32_t last_palette[16];
    uint16_t last_ch_attr[MAX_TEXT_WIDTH * MAX_TEXT_HEIGHT];
    uint32_t last_width;
    uint32_t last_height;
    uint16_t last_line_offset;
    uint16_t last_start_addr;
    uint16_t last_cursor_offset;
    uint8_t last_cursor_start;
    uint8_t last_cursor_end;
    
    /* VBE extension */
    uint16_t vbe_index;
    uint16_t vbe_regs[VBE_DISPI_INDEX_NB];
};

static void vga_draw_glyph8(uint8_t *d, int linesize,
                            const uint8_t *font_ptr, int h,
                            uint32_t fgcol, uint32_t bgcol)
{
    uint32_t font_data, xorcol;

    xorcol = bgcol ^ fgcol;
    do {
        font_data = font_ptr[0];
        ((uint32_t *)d)[0] = (-((font_data >> 7)) & xorcol) ^ bgcol;
        ((uint32_t *)d)[1] = (-((font_data >> 6) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[2] = (-((font_data >> 5) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[3] = (-((font_data >> 4) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[4] = (-((font_data >> 3) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[5] = (-((font_data >> 2) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[6] = (-((font_data >> 1) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[7] = (-((font_data >> 0) & 1) & xorcol) ^ bgcol;
        font_ptr++;
        d += linesize;
    } while (--h);
}

static void vga_draw_glyph9(uint8_t *d, int linesize,
                            const uint8_t *font_ptr, int h,
                            uint32_t fgcol, uint32_t bgcol,
                            int dup9)
{
    uint32_t font_data, xorcol, v;

    xorcol = bgcol ^ fgcol;
    do {
        font_data = font_ptr[0];
        ((uint32_t *)d)[0] = (-((font_data >> 7)) & xorcol) ^ bgcol;
        ((uint32_t *)d)[1] = (-((font_data >> 6) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[2] = (-((font_data >> 5) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[3] = (-((font_data >> 4) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[4] = (-((font_data >> 3) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[5] = (-((font_data >> 2) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[6] = (-((font_data >> 1) & 1) & xorcol) ^ bgcol;
        v = (-((font_data >> 0) & 1) & xorcol) ^ bgcol;
        ((uint32_t *)d)[7] = v;
        if (dup9)
            ((uint32_t *)d)[8] = v;
        else
            ((uint32_t *)d)[8] = bgcol;
        font_ptr++;
        d += linesize;
    } while (--h);
}

static const uint8_t cursor_glyph[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static inline int c6_to_8(int v)
{
    int b;
    v &= 0x3f;
    b = v & 1;
    return (v << 2) | (b << 1) | b;
}

static int update_palette16(VGAState *s, uint32_t *palette)
{
    int full_update, i;
    uint32_t v, col;

    full_update = 0;
    for(i = 0; i < 16; i++) {
        v = s->ar[i];
        if (s->ar[0x10] & 0x80)
            v = ((s->ar[0x14] & 0xf) << 4) | (v & 0xf);
        else
            v = ((s->ar[0x14] & 0xc) << 4) | (v & 0x3f);
        v = v * 3;
        col = (c6_to_8(s->palette[v]) << 16) |
            (c6_to_8(s->palette[v + 1]) << 8) |
            c6_to_8(s->palette[v + 2]);
        if (col != palette[i]) {
            full_update = 1;
            palette[i] = col;
        }
    }
    return full_update;
}

/* the text refresh is just for debugging and initial boot message, so
   it is very incomplete */
static void vga_text_refresh(VGAState *s,
                             SimpleFBDrawFunc *redraw_func, void *opaque)
{
    FBDevice *fb_dev = s->fb_dev;
    int width, height, cwidth, cheight, cy, cx, x1, y1, width1, height1;
    int cx_min, cx_max, dup9;
    uint32_t ch_attr, line_offset, start_addr, ch_addr, ch_addr1, ch, cattr;
    uint8_t *vga_ram, *font_ptr, *dst;
    uint32_t fgcol, bgcol, cursor_offset, cursor_start, cursor_end;
    BOOL full_update;

    full_update = update_palette16(s, s->last_palette);

    vga_ram = s->vga_ram;
    
    line_offset = s->cr[0x13];
    line_offset <<= 3;
    line_offset >>= 1;

    start_addr = s->cr[0x0d] | (s->cr[0x0c] << 8);
    
    cheight = (s->cr[9] & 0x1f) + 1;
    cwidth = 8;
    if (!(s->sr[1] & 0x01))
        cwidth++;
    
    width = (s->cr[0x01] + 1);
    height = s->cr[0x12] |
        ((s->cr[0x07] & 0x02) << 7) |
        ((s->cr[0x07] & 0x40) << 3);
    height = (height + 1) / cheight;
    
    width1 = width * cwidth;
    height1 = height * cheight;
    if (fb_dev->width < width1 || fb_dev->height < height1 ||
        width > MAX_TEXT_WIDTH || height > MAX_TEXT_HEIGHT)
        return; /* not enough space */
    if (s->last_line_offset != line_offset ||
        s->last_start_addr != start_addr ||
        s->last_width != width ||
        s->last_height != height) {
        s->last_line_offset = line_offset;
        s->last_start_addr = start_addr;
        s->last_width = width;
        s->last_height = height;
        full_update = TRUE;
    }
       
    /* update cursor position */
    cursor_offset = ((s->cr[0x0e] << 8) | s->cr[0x0f]) - start_addr;
    cursor_start = s->cr[0xa];
    cursor_end = s->cr[0xb];
    if (cursor_offset != s->last_cursor_offset ||
        cursor_start != s->last_cursor_start ||
        cursor_end != s->last_cursor_end) {
        /* force refresh of characters with the cursor */
        if (s->last_cursor_offset < MAX_TEXT_WIDTH * MAX_TEXT_HEIGHT)
            s->last_ch_attr[s->last_cursor_offset] = -1;
        if (cursor_offset < MAX_TEXT_WIDTH * MAX_TEXT_HEIGHT)
            s->last_ch_attr[cursor_offset] = -1;
        s->last_cursor_offset = cursor_offset;
        s->last_cursor_start = cursor_start;
        s->last_cursor_end = cursor_end;
    }

    ch_addr1 = 0x18000 + (start_addr * 2);
    cursor_offset = 0x18000 + (start_addr + cursor_offset) * 2;
    
    x1 = (fb_dev->width - width1) / 2;
    y1 = (fb_dev->height - height1) / 2;
#if 0
    printf("text refresh %dx%d font=%dx%d start_addr=0x%x line_offset=0x%x\n",
           width, height, cwidth, cheight, start_addr, line_offset);
#endif
    for(cy = 0; cy < height; cy++) {
        ch_addr = ch_addr1;
        dst = fb_dev->fb_data + (y1 + cy * cheight) * fb_dev->stride + x1 * 4;
        cx_min = width;
        cx_max = -1;
        for(cx = 0; cx < width; cx++) {
            ch_attr = *(uint16_t *)(vga_ram + (ch_addr & 0x1fffe));
            if (full_update || ch_attr != s->last_ch_attr[cy * width + cx]) {
                s->last_ch_attr[cy * width + cx] = ch_attr;
                cx_min = min_int(cx_min, cx);
                cx_max = max_int(cx_max, cx);
                ch = ch_attr & 0xff;
                cattr = ch_attr >> 8;
                font_ptr = vga_ram + 32 * ch;
                bgcol = s->last_palette[cattr >> 4];
                fgcol = s->last_palette[cattr & 0x0f];
                if (cwidth == 8) {
                    vga_draw_glyph8(dst, fb_dev->stride, font_ptr, cheight,
                                    fgcol, bgcol);
                } else {
                    dup9 = 0;
                    if (ch >= 0xb0 && ch <= 0xdf && (s->ar[0x10] & 0x04))
                        dup9 = 1;
                    vga_draw_glyph9(dst, fb_dev->stride, font_ptr, cheight,
                                    fgcol, bgcol, dup9);
                }
                /* cursor display */
                if (cursor_offset == ch_addr && !(cursor_start & 0x20)) {
                    int line_start, line_last, h;
                    uint8_t *dst1;
                    line_start = cursor_start & 0x1f;
                    line_last = min_int(cursor_end & 0x1f, cheight - 1);

                    if (line_last >= line_start && line_start < cheight) {
                        h = line_last - line_start + 1;
                        dst1 = dst + fb_dev->stride * line_start;
                        if (cwidth == 8) {
                            vga_draw_glyph8(dst1, fb_dev->stride,
                                            cursor_glyph,
                                            h, fgcol, bgcol);
                        } else {
                            vga_draw_glyph9(dst1, fb_dev->stride,
                                            cursor_glyph,
                                            h, fgcol, bgcol, 1);
                        }
                    }
                }
            }
            ch_addr += 2;
            dst += 4 * cwidth;
        }
        if (cx_max >= cx_min) {
            //            printf("redraw %d %d %d\n", cy, cx_min, cx_max);
            redraw_func(fb_dev, opaque,
                        x1 + cx_min * cwidth, y1 + cy * cheight,
                        (cx_max - cx_min + 1) * cwidth, cheight);
        }
        ch_addr1 += line_offset;
    }
}

static void vga_refresh(FBDevice *fb_dev,
                        SimpleFBDrawFunc *redraw_func, void *opaque)
{
    VGAState *s = fb_dev->device_opaque;

    if (!(s->ar_index & 0x20)) {
        /* blank */
    } else if (s->gr[0x06] & 1) {
        /* graphic mode (VBE) */
        simplefb_refresh(fb_dev, redraw_func, opaque, s->mem_range, s->fb_page_count);
    } else {
        /* text mode */
        vga_text_refresh(s, redraw_func, opaque);
    }
}

/* force some bits to zero */
static const uint8_t sr_mask[8] = {
    (uint8_t)~0xfc,
    (uint8_t)~0xc2,
    (uint8_t)~0xf0,
    (uint8_t)~0xc0,
    (uint8_t)~0xf1,
    (uint8_t)~0xff,
    (uint8_t)~0xff,
    (uint8_t)~0x00,
};

static const uint8_t gr_mask[16] = {
    (uint8_t)~0xf0, /* 0x00 */
    (uint8_t)~0xf0, /* 0x01 */
    (uint8_t)~0xf0, /* 0x02 */
    (uint8_t)~0xe0, /* 0x03 */
    (uint8_t)~0xfc, /* 0x04 */
    (uint8_t)~0x84, /* 0x05 */
    (uint8_t)~0xf0, /* 0x06 */
    (uint8_t)~0xf0, /* 0x07 */
    (uint8_t)~0x00, /* 0x08 */
    (uint8_t)~0xff, /* 0x09 */
    (uint8_t)~0xff, /* 0x0a */
    (uint8_t)~0xff, /* 0x0b */
    (uint8_t)~0xff, /* 0x0c */
    (uint8_t)~0xff, /* 0x0d */
    (uint8_t)~0xff, /* 0x0e */
    (uint8_t)~0xff, /* 0x0f */
};

static uint32_t vga_ioport_read(VGAState *s, uint32_t addr)
{
    int val, index;

    /* check port range access depending on color/monochrome mode */
    if ((addr >= 0x3b0 && addr <= 0x3bf && (s->msr & MSR_COLOR_EMULATION)) ||
        (addr >= 0x3d0 && addr <= 0x3df && !(s->msr & MSR_COLOR_EMULATION))) {
        val = 0xff;
    } else {
        switch(addr) {
        case 0x3c0:
            if (s->ar_flip_flop == 0) {
                val = s->ar_index;
            } else {
                val = 0;
            }
            break;
        case 0x3c1:
            index = s->ar_index & 0x1f;
            if (index < 21)
                val = s->ar[index];
            else
                val = 0;
            break;
        case 0x3c2:
            val = s->st00;
            break;
        case 0x3c4:
            val = s->sr_index;
            break;
        case 0x3c5:
            val = s->sr[s->sr_index];
#ifdef DEBUG_VGA_REG
            printf("vga: read SR%x = 0x%02x\n", s->sr_index, val);
#endif
            break;
        case 0x3c7:
            val = s->dac_state;
            break;
	case 0x3c8:
	    val = s->dac_write_index;
	    break;
        case 0x3c9:
            val = s->palette[s->dac_read_index * 3 + s->dac_sub_index];
            if (++s->dac_sub_index == 3) {
                s->dac_sub_index = 0;
                s->dac_read_index++;
            }
            break;
        case 0x3ca:
            val = s->fcr;
            break;
        case 0x3cc:
            val = s->msr;
            break;
        case 0x3ce:
            val = s->gr_index;
            break;
        case 0x3cf:
            val = s->gr[s->gr_index];
#ifdef DEBUG_VGA_REG
            printf("vga: read GR%x = 0x%02x\n", s->gr_index, val);
#endif
            break;
        case 0x3b4:
        case 0x3d4:
            val = s->cr_index;
            break;
        case 0x3b5:
        case 0x3d5:
            val = s->cr[s->cr_index];
#ifdef DEBUG_VGA_REG
            printf("vga: read CR%x = 0x%02x\n", s->cr_index, val);
#endif
            break;
        case 0x3ba:
        case 0x3da:
            /* just toggle to fool polling */
            s->st01 ^= ST01_V_RETRACE | ST01_DISP_ENABLE;
            val = s->st01;
            s->ar_flip_flop = 0;
            break;
        default:
            val = 0x00;
            break;
        }
    }
#if defined(DEBUG_VGA)
    printf("VGA: read addr=0x%04x data=0x%02x\n", addr, val);
#endif
    return val;
}

static void vga_ioport_write(VGAState *s, uint32_t addr, uint32_t val)
{
    int index;

    /* check port range access depending on color/monochrome mode */
    if ((addr >= 0x3b0 && addr <= 0x3bf && (s->msr & MSR_COLOR_EMULATION)) ||
        (addr >= 0x3d0 && addr <= 0x3df && !(s->msr & MSR_COLOR_EMULATION)))
        return;

#ifdef DEBUG_VGA
    printf("VGA: write addr=0x%04x data=0x%02x\n", addr, val);
#endif

    switch(addr) {
    case 0x3c0:
        if (s->ar_flip_flop == 0) {
            val &= 0x3f;
            s->ar_index = val;
        } else {
            index = s->ar_index & 0x1f;
            switch(index) {
            case 0x00 ... 0x0f:
                s->ar[index] = val & 0x3f;
                break;
            case 0x10:
                s->ar[index] = val & ~0x10;
                break;
            case 0x11:
                s->ar[index] = val;
                break;
            case 0x12:
                s->ar[index] = val & ~0xc0;
                break;
            case 0x13:
                s->ar[index] = val & ~0xf0;
                break;
            case 0x14:
                s->ar[index] = val & ~0xf0;
                break;
            default:
                break;
            }
        }
        s->ar_flip_flop ^= 1;
        break;
    case 0x3c2:
        s->msr = val & ~0x10;
        break;
    case 0x3c4:
        s->sr_index = val & 7;
        break;
    case 0x3c5:
#ifdef DEBUG_VGA_REG
        printf("vga: write SR%x = 0x%02x\n", s->sr_index, val);
#endif
        s->sr[s->sr_index] = val & sr_mask[s->sr_index];
        break;
    case 0x3c7:
        s->dac_read_index = val;
        s->dac_sub_index = 0;
        s->dac_state = 3;
        break;
    case 0x3c8:
        s->dac_write_index = val;
        s->dac_sub_index = 0;
        s->dac_state = 0;
        break;
    case 0x3c9:
        s->dac_cache[s->dac_sub_index] = val;
        if (++s->dac_sub_index == 3) {
            memcpy(&s->palette[s->dac_write_index * 3], s->dac_cache, 3);
            s->dac_sub_index = 0;
            s->dac_write_index++;
        }
        break;
    case 0x3ce:
        s->gr_index = val & 0x0f;
        break;
    case 0x3cf:
#ifdef DEBUG_VGA_REG
        printf("vga: write GR%x = 0x%02x\n", s->gr_index, val);
#endif
        s->gr[s->gr_index] = val & gr_mask[s->gr_index];
        break;
    case 0x3b4:
    case 0x3d4:
        s->cr_index = val;
        break;
    case 0x3b5:
    case 0x3d5:
#ifdef DEBUG_VGA_REG
        printf("vga: write CR%x = 0x%02x\n", s->cr_index, val);
#endif
        /* handle CR0-7 protection */
        if ((s->cr[0x11] & 0x80) && s->cr_index <= 7) {
            /* can always write bit 4 of CR7 */
            if (s->cr_index == 7)
                s->cr[7] = (s->cr[7] & ~0x10) | (val & 0x10);
            return;
        }
        switch(s->cr_index) {
        case 0x01: /* horizontal display end */
        case 0x07:
        case 0x09:
        case 0x0c:
        case 0x0d:
        case 0x12: /* vertical display end */
            s->cr[s->cr_index] = val;
            break;
        default:
            s->cr[s->cr_index] = val;
            break;
        }
        break;
    case 0x3ba:
    case 0x3da:
        s->fcr = val & 0x10;
        break;
    }
}

#define VGA_IO(base) \
static uint32_t vga_read_ ## base(void *opaque, uint32_t addr, int size_log2)\
{\
    return vga_ioport_read(opaque, base + addr);\
}\
static void vga_write_ ## base(void *opaque, uint32_t addr, uint32_t val, int size_log2)\
{\
    return vga_ioport_write(opaque, base + addr, val);\
}

VGA_IO(0x3c0)
VGA_IO(0x3b4)
VGA_IO(0x3d4)
VGA_IO(0x3ba)
VGA_IO(0x3da)

static void vbe_write(void *opaque, uint32_t offset,
                      uint32_t val, int size_log2)
{
    VGAState *s = opaque;
    FBDevice *fb_dev = s->fb_dev;
    
    if (offset == 0) {
        s->vbe_index = val;
    } else {
#ifdef DEBUG_VBE
        printf("VBE write: index=0x%04x val=0x%04x\n", s->vbe_index, val);
#endif
        switch(s->vbe_index) {
        case VBE_DISPI_INDEX_ID:
            if (val >= VBE_DISPI_ID0 && val <= VBE_DISPI_ID5)
                s->vbe_regs[s->vbe_index] = val;
            break;
        case VBE_DISPI_INDEX_ENABLE:
            if ((val & VBE_DISPI_ENABLED) &&
                !(s->vbe_regs[VBE_DISPI_INDEX_ENABLE] & VBE_DISPI_ENABLED)) {
                /* set graphic mode */
                /* XXX: resolution change not really supported */
                if (s->vbe_regs[VBE_DISPI_INDEX_XRES] <= 4096 &&
                    s->vbe_regs[VBE_DISPI_INDEX_YRES] <= 4096 &&
                    (s->vbe_regs[VBE_DISPI_INDEX_XRES] * 4 *
                     s->vbe_regs[VBE_DISPI_INDEX_YRES]) <= fb_dev->fb_size) {
                    fb_dev->width = s->vbe_regs[VBE_DISPI_INDEX_XRES];
                    fb_dev->height = s->vbe_regs[VBE_DISPI_INDEX_YRES];
                    fb_dev->stride = fb_dev->width * 4;
                }
                s->vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH] =
                    s->vbe_regs[VBE_DISPI_INDEX_XRES];
                s->vbe_regs[VBE_DISPI_INDEX_VIRT_HEIGHT] =
                    s->vbe_regs[VBE_DISPI_INDEX_YRES];
                s->vbe_regs[VBE_DISPI_INDEX_X_OFFSET] = 0;
                s->vbe_regs[VBE_DISPI_INDEX_Y_OFFSET] = 0;
            }
            s->vbe_regs[s->vbe_index] = val;
            break;
        case VBE_DISPI_INDEX_XRES:
        case VBE_DISPI_INDEX_YRES:
        case VBE_DISPI_INDEX_BPP:
        case VBE_DISPI_INDEX_BANK:
        case VBE_DISPI_INDEX_VIRT_WIDTH:
        case VBE_DISPI_INDEX_VIRT_HEIGHT:
        case VBE_DISPI_INDEX_X_OFFSET:
        case VBE_DISPI_INDEX_Y_OFFSET:
            s->vbe_regs[s->vbe_index] = val;
            break;
        }
    }
}

static uint32_t vbe_read(void *opaque, uint32_t offset, int size_log2)
{
    VGAState *s = opaque;
    uint32_t val;

    if (offset == 0) {
        val = s->vbe_index;
    } else {
        if (s->vbe_regs[VBE_DISPI_INDEX_ENABLE] & VBE_DISPI_GETCAPS) {
            switch(s->vbe_index) {
            case VBE_DISPI_INDEX_XRES:
                val = s->fb_dev->width;
                break;
            case VBE_DISPI_INDEX_YRES:
                val = s->fb_dev->height;
                break;
            case VBE_DISPI_INDEX_BPP:
                val = 32;
                break;
            default:
                goto read_reg;
            }
        } else {
        read_reg:
            if (s->vbe_index < VBE_DISPI_INDEX_NB)
                val = s->vbe_regs[s->vbe_index];
            else
                val = 0;
        }
#ifdef DEBUG_VBE
        printf("VBE read: index=0x%04x val=0x%04x\n", s->vbe_index, val);
#endif
    }
    return val;
}


static void simplefb_bar_set(void *opaque, int bar_num,
                              uint32_t addr, BOOL enabled)
{
    VGAState *s = opaque;
    if (bar_num == 0)
        phys_mem_set_addr(s->mem_range, addr, enabled);
    else
        phys_mem_set_addr(s->rom_range, addr, enabled);
}

VGAState *pci_vga_init(PCIBus *bus, FBDevice *fb_dev,
                       int width, int height,
                       const uint8_t *vga_rom_buf, int vga_rom_size)
{
    VGAState *s;
    PCIDevice *d;
    uint32_t bar_size;
    PhysMemoryMap *mem_map, *port_map;
    
    d = pci_register_device(bus, "VGA", -1, 0x1234, 0x1111, 0x00, 0x0300);
    
    mem_map = pci_device_get_mem_map(d);
    port_map = pci_device_get_port_map(d);

    s = mallocz(sizeof(*s));
    s->fb_dev = fb_dev;
    
    fb_dev->width = width;
    fb_dev->height = height;
    fb_dev->stride = width * 4;

    fb_dev->fb_size = (height * fb_dev->stride + FB_ALLOC_ALIGN - 1) & ~(FB_ALLOC_ALIGN - 1);
    s->fb_page_count = fb_dev->fb_size >> DEVRAM_PAGE_SIZE_LOG2;

    s->mem_range =
        cpu_register_ram(mem_map, 0, fb_dev->fb_size,
                         DEVRAM_FLAG_DIRTY_BITS | DEVRAM_FLAG_DISABLED);
    
    fb_dev->fb_data = s->mem_range->phys_mem;

    s->pci_dev = d;
    bar_size = 1;
    while (bar_size < fb_dev->fb_size)
        bar_size <<= 1;
    pci_register_bar(d, 0, bar_size, PCI_ADDRESS_SPACE_MEM, s,
                     simplefb_bar_set);

    if (vga_rom_size > 0) {
        int rom_size;
        /* align to page size */
        rom_size = (vga_rom_size + DEVRAM_PAGE_SIZE - 1) & ~(DEVRAM_PAGE_SIZE - 1);
        s->rom_range = cpu_register_ram(mem_map, 0, rom_size,
                                        DEVRAM_FLAG_ROM | DEVRAM_FLAG_DISABLED);
        memcpy(s->rom_range->phys_mem, vga_rom_buf, vga_rom_size);

        bar_size = 1;
        while (bar_size < rom_size)
            bar_size <<= 1;
        pci_register_bar(d, PCI_ROM_SLOT, bar_size, PCI_ADDRESS_SPACE_MEM, s,
                         simplefb_bar_set);
    }

    /* VGA memory (for simple text mode no need for callbacks) */
    s->mem_range2 = cpu_register_ram(mem_map, 0xa0000, 0x20000, 0);
    s->vga_ram = s->mem_range2->phys_mem;
        
    /* standard VGA ports */
    
    cpu_register_device(port_map, 0x3c0, 16, s, vga_read_0x3c0, vga_write_0x3c0,
                        DEVIO_SIZE8);
    cpu_register_device(port_map, 0x3b4, 2, s, vga_read_0x3b4, vga_write_0x3b4,
                        DEVIO_SIZE8);
    cpu_register_device(port_map, 0x3d4, 2, s, vga_read_0x3d4, vga_write_0x3d4,
                        DEVIO_SIZE8);
    cpu_register_device(port_map, 0x3ba, 1, s, vga_read_0x3ba, vga_write_0x3ba,
                        DEVIO_SIZE8);
    cpu_register_device(port_map, 0x3da, 1, s, vga_read_0x3da, vga_write_0x3da,
                        DEVIO_SIZE8);
    
    /* VBE extension */
    cpu_register_device(port_map, 0x1ce, 2, s, vbe_read, vbe_write, 
                        DEVIO_SIZE16);
    
    s->vbe_regs[VBE_DISPI_INDEX_ID] = VBE_DISPI_ID5;
    s->vbe_regs[VBE_DISPI_INDEX_VIDEO_MEMORY_64K] = fb_dev->fb_size >> 16;

    fb_dev->device_opaque = s;
    fb_dev->refresh = vga_refresh;
    return s;
}
