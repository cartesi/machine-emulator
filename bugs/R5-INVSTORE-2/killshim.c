// LD_PRELOAD shim: SIGKILL the process right before its Nth removal (unlink, unlinkat, remove, rmdir) of a chosen
// kind of path. This is a stop of the operator's process (kill, crash, power loss) at a chosen point.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int count;

// Environment:
//   KILL_MATCH       only paths containing this string are considered
//   KILL_EXCLUDE     ... and not containing this one (optional)
//   KILL_AFTER_FILE  ... and only once this file exists (optional)
//   KILL_NTH         SIGKILL right before the Nth considered removal
//   KILL_LOG         log every considered removal to stderr
static void maybe_kill(const char *path) {
    const char *match = getenv("KILL_MATCH");
    const char *exclude = getenv("KILL_EXCLUDE");
    const char *after = getenv("KILL_AFTER_FILE");
    const char *nth = getenv("KILL_NTH");
    if (!path || !match || !strstr(path, match)) return;
    if (exclude && *exclude && strstr(path, exclude)) return;
    if (after && *after && access(after, F_OK) != 0) return;
    if (getenv("KILL_LOG")) {
        (void) !write(2, "killshim: remove ", 17);
        (void) !write(2, path, strlen(path));
        (void) !write(2, "\n", 1);
    }
    if (nth && ++count == atoi(nth)) {
        static const char msg[] = "killshim: SIGKILL before removing ";
        (void) !write(2, msg, sizeof(msg) - 1);
        (void) !write(2, path, strlen(path));
        (void) !write(2, "\n", 1);
        kill(getpid(), SIGKILL);
    }
}

int unlink(const char *path) {
    static int (*real)(const char *);
    if (!real) real = (int (*)(const char *)) dlsym(RTLD_NEXT, "unlink");
    maybe_kill(path);
    return real(path);
}

int unlinkat(int dirfd, const char *path, int flags) {
    static int (*real)(int, const char *, int);
    if (!real) real = (int (*)(int, const char *, int)) dlsym(RTLD_NEXT, "unlinkat");
    maybe_kill(path);
    return real(dirfd, path, flags);
}

int remove(const char *path) {
    static int (*real)(const char *);
    if (!real) real = (int (*)(const char *)) dlsym(RTLD_NEXT, "remove");
    maybe_kill(path);
    return real(path);
}

int rmdir(const char *path) {
    static int (*real)(const char *);
    if (!real) real = (int (*)(const char *)) dlsym(RTLD_NEXT, "rmdir");
    maybe_kill(path);
    return real(path);
}
