// LD_PRELOAD shim: make one chosen renameat2() or unlink() call fail with EIO, a host I/O fault. The process is
// not stopped: it sees the error and keeps running its own error handling.
//
// Environment:
//   FAIL_FUNC        "renameat2" or "unlink"
//   FAIL_SUFFIX      renameat2: only calls whose source path ends with this string are considered
//   FAIL_MATCH       unlink: only paths containing this string are considered
//   FAIL_AFTER_FILE  ... and only once this file exists (optional)
//   FAIL_NTH         fail the Nth considered call (default 1); every other call goes through
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int count;

static void note(const char *what, const char *path) {
    (void) !write(2, "ioshim: failing ", 16);
    (void) !write(2, what, strlen(what));
    (void) !write(2, " ", 1);
    (void) !write(2, path, strlen(path));
    (void) !write(2, " with EIO\n", 10);
}

static int should_fail(const char *func, const char *path) {
    const char *f = getenv("FAIL_FUNC");
    if (!f || strcmp(f, func) != 0 || !path) return 0;
    if (strcmp(func, "renameat2") == 0) {
        const char *suffix = getenv("FAIL_SUFFIX");
        size_t lp = strlen(path), ls = suffix ? strlen(suffix) : 0;
        if (!suffix || lp < ls || strcmp(path + lp - ls, suffix) != 0) return 0;
    } else {
        const char *match = getenv("FAIL_MATCH");
        if (!match || !strstr(path, match)) return 0;
    }
    const char *after = getenv("FAIL_AFTER_FILE");
    if (after && *after && access(after, F_OK) != 0) return 0;
    const char *nth = getenv("FAIL_NTH");
    return ++count == (nth ? atoi(nth) : 1);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    static int (*real)(int, const char *, int, const char *, unsigned int);
    if (!real) real = (int (*)(int, const char *, int, const char *, unsigned int)) dlsym(RTLD_NEXT, "renameat2");
    if (should_fail("renameat2", oldpath)) {
        note("renameat2", oldpath);
        errno = EIO;
        return -1;
    }
    return real(olddirfd, oldpath, newdirfd, newpath, flags);
}

int unlink(const char *path) {
    static int (*real)(const char *);
    if (!real) real = (int (*)(const char *)) dlsym(RTLD_NEXT, "unlink");
    if (should_fail("unlink", path)) {
        note("unlink", path);
        errno = EIO;
        return -1;
    }
    return real(path);
}
