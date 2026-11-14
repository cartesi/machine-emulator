// Fault injector for bugs/R3-VARDIRTY-1 (LD_PRELOAD): simulates one host allocation failure.
//
// Replaces the global operator new. While the file named by FAIL_NEW_ARM_FILE exists, the first request of
// exactly FAIL_NEW_EXACT bytes throws std::bad_alloc, as an allocator under a memory limit would. Every other
// request is served by malloc. Each injected failure appends its size to FAIL_NEW_COUNT_FILE. FAIL_NEW_LOG=1
// logs requests of at least 1024 bytes made while armed.
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <unistd.h>

namespace {

size_t exact_size() {
    static size_t v = [] {
        const char *s = std::getenv("FAIL_NEW_EXACT");
        return s != nullptr ? static_cast<size_t>(std::strtoull(s, nullptr, 0)) : static_cast<size_t>(0);
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

int injected = 0;

void *alloc(size_t n) {
    if (n >= 1024 && armed()) {
        if (logging()) {
            std::fprintf(stderr, "fail-new: armed request of %zu bytes\n", n);
        }
        if (n == exact_size() && injected == 0) {
            ++injected;
            if (const char *f = std::getenv("FAIL_NEW_COUNT_FILE"); f != nullptr) {
                if (FILE *fp = std::fopen(f, "a"); fp != nullptr) {
                    std::fprintf(fp, "%zu\n", n);
                    std::fclose(fp);
                }
            }
            throw std::bad_alloc();
        }
    }
    void *p = std::malloc(n == 0 ? 1 : n);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

void *alloc_aligned(size_t n, std::align_val_t a) {
    std::free(alloc(n)); // same injection policy
    void *p = nullptr;
    size_t al = static_cast<size_t>(a) < sizeof(void *) ? sizeof(void *) : static_cast<size_t>(a);
    if (posix_memalign(&p, al, n == 0 ? 1 : n) != 0) {
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
void *operator new(size_t n, const std::nothrow_t &) noexcept {
    try {
        return alloc(n);
    } catch (...) {
        return nullptr;
    }
}
void *operator new[](size_t n, const std::nothrow_t &) noexcept {
    try {
        return alloc(n);
    } catch (...) {
        return nullptr;
    }
}
void *operator new(size_t n, std::align_val_t a) {
    return alloc_aligned(n, a);
}
void *operator new[](size_t n, std::align_val_t a) {
    return alloc_aligned(n, a);
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
void operator delete(void *p, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete(void *p, size_t, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, size_t, std::align_val_t) noexcept {
    std::free(p);
}
