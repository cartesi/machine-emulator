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
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <signal.h>
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

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
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

typedef enum {
    BF_MODE_RO,
    BF_MODE_RW,
    BF_MODE_SNAPSHOT,
} BlockDeviceModeEnum;

#define SECTOR_SIZE 512

typedef struct BlockDeviceFile {
    FILE *f;
    int64_t nb_sectors;
    BlockDeviceModeEnum mode;
    uint8_t **sector_table;
} BlockDeviceFile;

static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceFile *bf = bs->opaque;
    return bf->nb_sectors;
}

//#define DUMP_BLOCK_READ

static int bf_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    //    printf("bf_read_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
#ifdef DUMP_BLOCK_READ
    {
        static FILE *f;
        if (!f)
            f = fopen("/tmp/read_sect.txt", "wb");
        fprintf(f, "%" PRId64 " %d\n", sector_num, n);
    }
#endif
    if (!bf->f)
        return -1;
    if (bf->mode == BF_MODE_SNAPSHOT) {
        int i;
        for(i = 0; i < n; i++) {
            if (!bf->sector_table[sector_num]) {
                fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
                fread(buf, 1, SECTOR_SIZE, bf->f);
            } else {
                memcpy(buf, bf->sector_table[sector_num], SECTOR_SIZE);
            }
            sector_num++;
            buf += SECTOR_SIZE;
        }
    } else {
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fread(buf, 1, n * SECTOR_SIZE, bf->f);
    }
    /* synchronous read */
    return 0;
}

static int bf_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    int ret;

    switch(bf->mode) {
    case BF_MODE_RO:
        ret = -1; /* error */
        break;
    case BF_MODE_RW:
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fwrite(buf, 1, n * SECTOR_SIZE, bf->f);
        ret = 0;
        break;
    case BF_MODE_SNAPSHOT:
        {
            int i;
            if ((sector_num + n) > bf->nb_sectors)
                return -1;
            for(i = 0; i < n; i++) {
                if (!bf->sector_table[sector_num]) {
                    bf->sector_table[sector_num] = malloc(SECTOR_SIZE);
                }
                memcpy(bf->sector_table[sector_num], buf, SECTOR_SIZE);
                sector_num++;
                buf += SECTOR_SIZE;
            }
            ret = 0;
        }
        break;
    default:
        abort();
    }

    return ret;
}

static BlockDevice *block_device_init(const char *filename,
                                      BlockDeviceModeEnum mode)
{
    BlockDevice *bs;
    BlockDeviceFile *bf;
    int64_t file_size;
    FILE *f;
    const char *mode_str;

    if (mode == BF_MODE_RW) {
        mode_str = "r+b";
    } else {
        mode_str = "rb";
    }

    f = fopen(filename, mode_str);
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    file_size = ftello(f);

    bs = mallocz(sizeof(*bs));
    bf = mallocz(sizeof(*bf));

    bf->mode = mode;
    bf->nb_sectors = file_size / 512;
    bf->f = f;

    if (mode == BF_MODE_SNAPSHOT) {
        bf->sector_table = mallocz(sizeof(bf->sector_table[0]) *
                                   bf->nb_sectors);
    }

    bs->opaque = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->read_async = bf_read_async;
    bs->write_async = bf_write_async;
    return bs;
}

#define MAX_EXEC_CYCLE 500000
#define MAX_SLEEP_TIME 10 /* in ms */

void virt_machine_run(VirtMachine *m)
{
    fd_set rfds, wfds, efds;
    int fd_max, ret, delay;
    struct timeval tv;
#ifndef _WIN32
    int stdin_fd;
#endif

    delay = virt_machine_get_sleep_duration(m, MAX_SLEEP_TIME);

    /* wait for an event */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    fd_max = -1;
#ifndef _WIN32
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
#endif
    tv.tv_sec = delay / 1000;
    tv.tv_usec = delay % 1000;
    ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
    if (ret > 0) {
#ifndef _WIN32
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
#endif
    }

    virt_machine_interp(m, MAX_EXEC_CYCLE);
}

/*******************************************************/

static struct option options[] = {
    { "help", no_argument, NULL, 'h' },
    { "ctrlc", no_argument },
    { "rw", no_argument },
    { "ro", no_argument },
    { "append", required_argument },
    { "no-accel", no_argument },
    { NULL },
};

void help(void)
{
    printf("riscvemu version " CONFIG_VERSION ", Copyright (c) 2016-2017 Fabrice Bellard\n"
           "usage: riscvemu [options] config_file\n"
           "options are:\n"
           "-m ram_size       set the RAM size in MB\n"
           "-rw               allow write access to the disk image (default=snapshot)\n"
           "-ctrlc            the C-c key stops the emulator instead of being sent to the\n"
           "                  emulated software\n"
           "-append cmdline   append cmdline to the kernel command line\n"
           "\n"
           "Console keys:\n"
           "Press C-a x to exit the emulator, C-a h to get some help.\n");
    exit(1);
}

int main(int argc, char **argv)
{
    VirtMachine *s;
    const char *path, *cmdline;
    int c, option_index, i, ram_size;
    BOOL allow_ctrlc;
    BlockDeviceModeEnum drive_mode;
    VirtMachineParams p_s, *p = &p_s;

    ram_size = -1;
    allow_ctrlc = FALSE;
    (void)allow_ctrlc;
    drive_mode = BF_MODE_SNAPSHOT;
    cmdline = NULL;
    for(;;) {
        c = getopt_long_only(argc, argv, "hb:m:", options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 0:
            switch(option_index) {
            case 1: /* ctrlc */
                allow_ctrlc = TRUE;
                break;
            case 2: /* rw */
                drive_mode = BF_MODE_RW;
                break;
            case 3: /* ro */
                drive_mode = BF_MODE_RO;
                break;
            case 4: /* append */
                cmdline = optarg;
                break;
            default:
                fprintf(stderr, "unknown option index: %d\n", option_index);
                exit(1);
            }
            break;
        case 'h':
            help();
            break;
        case 'm':
            ram_size = (uint64_t)strtoul(optarg, NULL, 0) << 20;
            break;
        default:
            exit(1);
        }
    }

    if (optind >= argc) {
        help();
    }

    path = argv[optind++];

    virt_machine_set_defaults(p);
    virt_machine_load_config_file(p, path, NULL, NULL);

    /* override some config parameters */

    if (ram_size > 0) {
        p->ram_size = ram_size << 20;
    }

    if (cmdline) {
        vm_add_cmdline(p, cmdline);
    }

    /* open the files & devices */
    for(i = 0; i < p->drive_count; i++) {
        BlockDevice *drive;
        char *fname;
        fname = get_file_path(p->cfg_filename, p->tab_drive[i].filename);
        drive = block_device_init(fname, drive_mode);
        free(fname);
        p->tab_drive[i].block_dev = drive;
    }

    for(i = 0; i < p->fs_count; i++) {
        FSDevice *fs;
        const char *path;
        char *fname;
        path = p->tab_fs[i].filename;
        fname = get_file_path(p->cfg_filename, path);
        fs = fs_disk_init(fname);
        if (!fs) {
            fprintf(stderr, "%s: must be a directory\n", fname);
            exit(1);
        }
        free(fname);
        p->tab_fs[i].fs_dev = fs;
    }

    p->console = console_init(allow_ctrlc);
    p->rtc_real_time = TRUE;

    s = virt_machine_init(p);

    virt_machine_free_config(p);

    for(;;) {
        virt_machine_run(s);
    }
    virt_machine_end(s);
    return 0;
}
