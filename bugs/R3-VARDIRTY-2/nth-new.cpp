// LD_PRELOAD fault injector for bugs/R3-VARDIRTY-2.
// It replaces the global operator new. While the file named by $NTH_ARM_FILE exists, it counts every
// operator new request. If $NTH is N > 0, it throws std::bad_alloc for the N-th counted request, once, as an
// allocator under a memory limit would. At exit it writes the number of counted requests and whether it
// injected (format "<count> <injected 0|1>") to $NTH_COUNT_FILE.
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <sys/stat.h>

namespace {
long g_counter = 0;
bool g_injected = false;

bool armed() {
    static const char *f = std::getenv("NTH_ARM_FILE");
    struct stat st {};
    return f != nullptr && stat(f, &st) == 0;
}

void count_and_maybe_fail() {
    static const long nth = std::getenv("NTH") != nullptr ? std::atol(std::getenv("NTH")) : 0;
    if (armed()) {
        ++g_counter;
        if (nth > 0 && !g_injected && g_counter == nth) {
            g_injected = true;
            throw std::bad_alloc();
        }
    }
}

struct reporter {
    ~reporter() {
        const char *f = std::getenv("NTH_COUNT_FILE");
        if (f != nullptr) {
            if (FILE *fp = std::fopen(f, "w")) {
                std::fprintf(fp, "%ld %d\n", g_counter, g_injected ? 1 : 0);
                std::fclose(fp);
            }
        }
    }
} g_reporter;

void *plain(std::size_t n) {
    count_and_maybe_fail();
    void *p = std::malloc(n != 0 ? n : 1);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

void *aligned(std::size_t n, std::align_val_t a) {
    count_and_maybe_fail();
    auto al = static_cast<std::size_t>(a);
    if (al < sizeof(void *)) {
        al = sizeof(void *);
    }
    void *p = nullptr;
    if (posix_memalign(&p, al, n != 0 ? n : 1) != 0) {
        throw std::bad_alloc();
    }
    return p;
}
} // namespace

void *operator new(std::size_t n) {
    return plain(n);
}
void *operator new[](std::size_t n) {
    return plain(n);
}
void *operator new(std::size_t n, std::align_val_t a) {
    return aligned(n, a);
}
void *operator new[](std::size_t n, std::align_val_t a) {
    return aligned(n, a);
}
void *operator new(std::size_t n, const std::nothrow_t &) noexcept {
    try {
        return plain(n);
    } catch (...) {
        return nullptr;
    }
}
void *operator new[](std::size_t n, const std::nothrow_t &) noexcept {
    try {
        return plain(n);
    } catch (...) {
        return nullptr;
    }
}
void operator delete(void *p) noexcept {
    std::free(p);
}
void operator delete[](void *p) noexcept {
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::size_t) noexcept {
    std::free(p);
}
void operator delete(void *p, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete(void *p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}
