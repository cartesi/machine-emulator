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
    BOOL resize_pending;
    struct termios oldtty;
    int old_fd0_flags;
} STDIODevice;

static void term_init(STDIODevice *s)
{
    struct termios tty;

    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    s->oldtty = tty;
    s->old_fd0_flags = fcntl(0, F_GETFL);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr (0, TCSANOW, &tty);
}

static void term_end(STDIODevice *s)
{
    tcsetattr (0, TCSANOW, &s->oldtty);
    fcntl(0, F_SETFL, s->old_fd0_flags);
}

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}

static int console_read(void *opaque, uint8_t *buf, int len)
{
    STDIODevice *s = opaque;
    int ret;

    if (len <= 0)
        return 0;

    ret = read(s->stdin_fd, buf, len);
#if 0
    if (ret < 0)
        return 0;
    if (ret == 0) {
        /* EOF: i.e., the console was redirected and the
         * file ended */
        fprintf(stderr, "EOF\n");
        exit(1);
    }
#endif
    if (ret <= 0)
        return 0;
    return ret;
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

CharacterDevice *console_init(void)
{
    CharacterDevice *dev;
    STDIODevice *s;

    dev = mallocz(sizeof(*dev));
    s = mallocz(sizeof(*s));

    term_init(s);

    s->stdin_fd = 0;
    /* Note: the glibc does not properly tests the return value of
       write() in printf, so some messages on stdout may be lost */
    fcntl(s->stdin_fd, F_SETFL, O_NONBLOCK);

    s->resize_pending = TRUE;

    dev->opaque = s;
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

static void console_end(CharacterDevice *dev) {
    STDIODevice *s = dev->opaque;
    term_end(s);
    free(s);
    free(dev);
}

#define MAX_EXEC_CYCLE 500000

static int virt_machine_run(VirtMachine *m)
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

    return virt_machine_interp(m, MAX_EXEC_CYCLE);
}

/*******************************************************/

static int emu_lua_run(lua_State *L) {
    VirtMachine *s;
    VirtMachineParams p_s, *p = &p_s;

    virt_lua_load_config(L, p, 1);

    p->console = console_init();

    s = virt_machine_init(p);

    virt_machine_free_config(p);

    if (!s) {
        luaL_error(L, "Failed to initialize machine.");
    }

    /* repeat interpreter run until shuthost */
    while (!virt_machine_run(s)) {
        ;
    }


    console_end(p->console);

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
