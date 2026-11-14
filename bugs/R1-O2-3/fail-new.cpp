// Fault injector for bugs/R1-O2-3 (LD_PRELOAD): simulates a host allocation failure.
//
// Replaces the global operator new. While the file named by FAIL_NEW_ARM_FILE exists, every request of at
// least FAIL_NEW_MIN_SIZE bytes throws std::bad_alloc, as an allocator under a memory limit would. Smaller
// requests, and all requests while the file is absent, are served by malloc. FAIL_NEW_LOG=1 logs large
// requests and the injected failures to stderr. The file is only checked for large requests, so the cost is
// negligible.
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <unistd.h>

namespace {

size_t min_size() {
    static size_t v = [] {
        const char *s = std::getenv("FAIL_NEW_MIN_SIZE");
        return s != nullptr ? static_cast<size_t>(std::strtoull(s, nullptr, 0)) : static_cast<size_t>(-1);
    }();
    return v;
}

bool armed() {
    const char *f = std::getenv("FAIL_NEW_ARM_FILE");
    return f != nullptr && access(f, F_OK) == 0;
}

bool logging() {
    static bool v = std::getenv("FAIL_NEW_LOG") != nullptr;
    return v;
}

void *alloc(size_t n) {
    if (n >= min_size() && armed()) {
        if (logging()) {
            std::fprintf(stderr, "fail-new: injected std::bad_alloc for %zu bytes\n", n);
        }
        // Count the injected failures in a file next to the arm file (read by the test)
        if (const char *f = std::getenv("FAIL_NEW_COUNT_FILE"); f != nullptr) {
            if (FILE *fp = std::fopen(f, "a"); fp != nullptr) {
                std::fprintf(fp, "%zu\n", n);
                std::fclose(fp);
            }
        }
        throw std::bad_alloc();
    }
    if (logging() && n >= 16384) {
        std::fprintf(stderr, "fail-new: %zu bytes (armed=%d)\n", n, armed() ? 1 : 0);
    }
    void *p = std::malloc(n == 0 ? 1 : n);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

} // namespace

void *operator new(size_t n) {
    return alloc(n);
}
void *operator new[](size_t n) {
    return alloc(n);
}
void operator delete(void *p) noexcept {
    std::free(p);
}
void operator delete[](void *p) noexcept {
    std::free(p);
}
void operator delete(void *p, size_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, size_t) noexcept {
    std::free(p);
}
