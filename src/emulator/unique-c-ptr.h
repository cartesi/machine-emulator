#ifndef UNIQUE_C_PTR
#define UNIQUE_C_PTR

#include <memory>
#include <cstdlib>
#include <cstdio>

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
    return unique_calloc_ptr<T>(reinterpret_cast<T *>(calloc(nmemb, size)));
}

static inline unique_file_ptr unique_fopen(const char *pathname, const char *mode) {
    return unique_file_ptr(fopen(pathname, mode));
}

#endif
