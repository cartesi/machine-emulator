#ifndef UNIQUE_C_PTR
#define UNIQUE_C_PTR

#include <memory>
#include <new>
#include <cstdlib>
#include <cstdio>

namespace cartesi {

namespace detail {
    struct free_deleter {
        template <typename T>
        void operator()(T *p) const {
            std::free(const_cast<std::remove_const_t<T> *>(p));
        }
    };

    struct fclose_deleter {
        void operator()(FILE *p) const {
            std::fclose(p);
        }
    };
}

template <typename T>
using unique_calloc_ptr = std::unique_ptr<T, detail::free_deleter>;

using unique_file_ptr = std::unique_ptr<FILE, detail::fclose_deleter>;

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(size_t nmemb, size_t size) {
    T *ptr = reinterpret_cast<T *>(calloc(nmemb, size));
    if (!ptr) throw std::bad_alloc{};
    return unique_calloc_ptr<T>(ptr);
}

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(void) {
    return unique_calloc<T>(1, sizeof(T));
}

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(size_t nmemb, size_t size, const std::nothrow_t &tag) {
    (void) tag;
    return unique_calloc_ptr<T>(reinterpret_cast<T *>(calloc(nmemb, size)));
}

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(const std::nothrow_t &tag) {
    return unique_calloc<T>(1, sizeof(T), tag);
}

static inline unique_file_ptr unique_fopen(const char *pathname, const char *mode) {
    FILE *fp = fopen(pathname, mode);
    if (!fp)
        throw std::system_error(errno, std::generic_category(),
            "unable to open '" + std::string{pathname} +
            "' in mode '" + std::string{mode} + "'");
    return unique_file_ptr{fp};
}

static inline unique_file_ptr unique_fopen(const char *pathname, const char *mode, const std::nothrow_t &tag) {
    (void) tag;
    return unique_file_ptr{fopen(pathname, mode)};
}

} // namespace cartesi

#endif
