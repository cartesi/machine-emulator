#ifndef OS_POSIX_COMPAT_H
#define OS_POSIX_COMPAT_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>

#include <direct.h> // mkdir
#include <io.h>     // _write/_close
#include <sys/stat.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#define UTIME_NOW -1
#define UTIME_OMIT -2

#ifdef mkdir
#undef mkdir
#endif

#ifndef write
#define write _write
#endif

#ifndef read
#define read _read
#endif

#ifndef close
#define close _close
#endif

#ifndef dup
#define dup _dup
#endif

#define lstat stat

[[maybe_unused]] static int fsync(int fd) {
    HANDLE h = (HANDLE) _get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    if (!FlushFileBuffers(h)) {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

[[maybe_unused]] static ssize_t pread(int fd, void *buf, size_t count, uint64_t offset) {
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
    DWORD dwBytesRead = 0;
    OVERLAPPED ovl{};
    ovl.Offset = (DWORD) offset;
    ovl.OffsetHigh = (DWORD) (offset >> 32);
    SetLastError(0);
    if (!ReadFile(hFile, buf, (DWORD) count, &dwBytesRead, &ovl) && GetLastError() != ERROR_HANDLE_EOF) {
        errno = GetLastError();
        return -1;
    }
    return dwBytesRead;
}

[[maybe_unused]] static ssize_t pwrite(int fd, const void *buf, size_t count, uint64_t offset) {
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
    DWORD dwBytesWritten = 0;
    OVERLAPPED ovl{};
    ovl.Offset = (DWORD) offset;
    ovl.OffsetHigh = (DWORD) (offset >> 32);
    SetLastError(0);
    if (!WriteFile(hFile, buf, (DWORD) count, &dwBytesWritten, &ovl) && GetLastError() != ERROR_HANDLE_EOF) {
        errno = GetLastError();
        return -1;
    }
    return dwBytesWritten;
}

[[maybe_unused]] static int futimens(int fd, const struct timespec times[2]) {
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    FILETIME now{}, aft{}, mft{};
    FILETIME *pft[2] = {&aft, &mft};
    GetSystemTimeAsFileTime(&now);
    if (times) {
        for (int i = 0; i < 2; ++i) {
            if (times[i].tv_nsec == UTIME_NOW) {
                *pft[i] = now;
            } else if (times[i].tv_nsec == UTIME_OMIT) {
                pft[i] = NULL;
            } else if (times[i].tv_nsec >= 0 && times[i].tv_nsec < 1000000000L) {
                long long winTime = times[i].tv_sec * 10000000LL + times[i].tv_nsec / 100LL + 116444736000000000LL;
                pft[i]->dwLowDateTime = winTime;
                pft[i]->dwHighDateTime = winTime >> 32;
            } else {
                errno = EINVAL;
                return -1;
            }
        }
    } else {
        aft = mft = now;
    }
    if (!SetFileTime(hFile, NULL, pft[0], pft[1])) {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

[[maybe_unused]] static int link(const char * /*from*/, const char * /*to*/) {
    errno = ENOTSUP;
    return -1;
}

[[maybe_unused]] static int fchmod(int fd, mode_t mode) {
    // Validate file descriptor
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    // Convert file descriptor to Windows HANDLE
    HANDLE hFile = (HANDLE) _get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    // Get file path from handle
    char filePath[MAX_PATH]{};
    DWORD pathLen = GetFinalPathNameByHandleA(hFile, filePath, MAX_PATH, FILE_NAME_NORMALIZED);
    if (pathLen == 0 || pathLen >= MAX_PATH) {
        errno = (pathLen >= MAX_PATH) ? ENAMETOOLONG : EBADF;
        return -1;
    }

    // Get current attributes
    DWORD attributes = GetFileAttributesA(filePath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        errno = EBADF;
        return -1;
    }

    // Windows can really only represent the write permission as a read-only flag
    // If any write permission is set, clear the read-only attribute; otherwise, set it
    if (mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
        attributes &= ~FILE_ATTRIBUTE_READONLY;
    } else {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }

    // Apply the new attributes
    if (!SetFileAttributesA(filePath, attributes)) {
        errno = EACCES;
        return -1;
    }

    return 0;
}

[[maybe_unused]] static int mkdir(const char *dirname, mode_t /*mode*/) {
    return _mkdir(dirname);
}

#endif // _WIN32

#include <fcntl.h> // IWYU pragma: keep

#ifndef O_BINARY
#define O_BINARY 0 // NOLINT(cppcoreguidelines-macro-usage)
#endif

#endif // OS_POSIX_COMPAT_H
