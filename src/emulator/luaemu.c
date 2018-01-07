/*
 * RISCV emulator
 *
 * Copyright (c) 2016-2017 Fabrice Bellard
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
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>

#include <lua.h>
#include <lauxlib.h>

#include "cutils.h"
#include "iomem.h"
#include "virtio.h"
#include "machine.h"
#include "riscv_cpu.h"

typedef struct {
    int stdin_fd;
    int console_esc_state;
    BOOL resize_pending;
} STDIODevice;

static struct termios oldtty;
static int old_fd0_flags;
static STDIODevice *global_stdio_device;

static void term_exit(void)
{
    tcsetattr (0, TCSANOW, &oldtty);
    fcntl(0, F_SETFL, old_fd0_flags);
}

static void term_init(BOOL allow_ctrlc)
{
    struct termios tty;

    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    oldtty = tty;
    old_fd0_flags = fcntl(0, F_GETFL);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    if (!allow_ctrlc)
        tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr (0, TCSANOW, &tty);

    atexit(term_exit);
}

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}

static int console_read(void *opaque, uint8_t *buf, int len)
{
    STDIODevice *s = opaque;
    int ret, i, j;
    uint8_t ch;

    if (len <= 0)
        return 0;

    ret = read(s->stdin_fd, buf, len);
    if (ret < 0)
        return 0;
    if (ret == 0) {
        /* EOF */
        exit(1);
    }

    j = 0;
    for(i = 0; i < ret; i++) {
        ch = buf[i];
        if (s->console_esc_state) {
            s->console_esc_state = 0;
            switch(ch) {
            case 'x':
                printf("Terminated\n");
                exit(0);
            case 'h':
                printf("\n"
                       "C-a h   print this help\n"
                       "C-a x   exit emulator\n"
                       "C-a C-a send C-a\n");
                break;
            case 1:
                goto output_char;
            default:
                break;
            }
        } else {
            if (ch == 1) {
                s->console_esc_state = 1;
            } else {
            output_char:
                buf[j++] = ch;
            }
        }
    }
    return j;
}

static void term_resize_handler(int sig)
{
    if (global_stdio_device)
        global_stdio_device->resize_pending = TRUE;
}

static void console_get_size(STDIODevice *s, int *pw, int *ph)
{
    struct winsize ws;
    int width, height;
    /* default values */
    width = 80;
    height = 25;
    if (ioctl(s->stdin_fd, TIOCGWINSZ, &ws) == 0 &&
        ws.ws_col >= 4 && ws.ws_row >= 4) {
        width = ws.ws_col;
        height = ws.ws_row;
    }
    *pw = width;
    *ph = height;
}

CharacterDevice *console_init(BOOL allow_ctrlc)
{
    CharacterDevice *dev;
    STDIODevice *s;
    struct sigaction sig;

    term_init(allow_ctrlc);

    dev = mallocz(sizeof(*dev));
    s = mallocz(sizeof(*s));
    s->stdin_fd = 0;
    /* Note: the glibc does not properly tests the return value of
       write() in printf, so some messages on stdout may be lost */
    fcntl(s->stdin_fd, F_SETFL, O_NONBLOCK);

    s->resize_pending = TRUE;
    global_stdio_device = s;

    /* use a signal to get the host terminal resize events */
    sig.sa_handler = term_resize_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sigaction(SIGWINCH, &sig, NULL);

    dev->opaque = s;
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

#define MAX_EXEC_CYCLE 500000

void virt_machine_run(VirtMachine *m)
{
    fd_set rfds, wfds, efds;
    int fd_max, ret;
    struct timeval tv;
    int stdin_fd;

    virt_machine_advance_cycle_counter(m);

    /* wait for an event */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    fd_max = -1;
    if (m->console_dev && virtio_console_can_write_data(m->console_dev)) {
        STDIODevice *s = m->console->opaque;
        stdin_fd = s->stdin_fd;
        FD_SET(stdin_fd, &rfds);
        fd_max = stdin_fd;

        if (s->resize_pending) {
            int width, height;
            console_get_size(s, &width, &height);
            virtio_console_resize_event(m->console_dev, width, height);
            s->resize_pending = FALSE;
        }
    }
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
    if (ret > 0) {
        if (m->console_dev && FD_ISSET(stdin_fd, &rfds)) {
            uint8_t buf[128];
            int ret, len;
            len = virtio_console_get_write_len(m->console_dev);
            len = min_int(len, sizeof(buf));
            ret = m->console->read_data(m->console->opaque, buf, len);
            if (ret > 0) {
                virtio_console_write_data(m->console_dev, buf, ret);
            }
        }
    }

    virt_machine_interp(m, MAX_EXEC_CYCLE);
}

/*******************************************************/

static int emu_lua_run(lua_State *L) {
    VirtMachine *s;
    VirtMachineParams p_s, *p = &p_s;

    virt_lua_load_config(L, p, 1);

    p->console = console_init(FALSE);

    s = virt_machine_init(p);

    virt_machine_free_config(p);

    for ( ;; ) {
        virt_machine_run(s);
    }
    virt_machine_end(s);
    return 0;
}

static const luaL_Reg emu_lua[] = {
    {"run", emu_lua_run},
    { NULL, NULL }
};

__attribute__((visibility("default")))
int luaopen_emu(lua_State *L) {
    lua_newtable(L);
    luaL_setfuncs(L, emu_lua, 0);
    return 1;
}
