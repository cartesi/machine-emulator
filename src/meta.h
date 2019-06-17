#ifndef META_H
#define META_H

#include <type_traits>

/// \file
/// \brief Meta-programming helper functions.

namespace cartesi {

/// \brief Converts a strongly typed constant to its underlying integer type
template <typename E>
constexpr auto to_underlying(E e) noexcept {
    return static_cast<std::underlying_type_t<E>>(e);
}

namespace detail {
    template <template<typename...> class BASE, typename DERIVED>
    struct is_template_base_of_helper {
        struct no {};
        struct yes {};
        no operator()(...);
        template <typename ...T>
        yes operator()(const BASE<T...> &);
    };
}

/// \class remove_cvref
/// \brief Provides a member typedef type with reference and topmost cv-qualifiers removed.
/// \note (This is directly available in C++20.)
template <typename T>
struct remove_cvref {
    typedef typename
        std::remove_reference<typename
            std::remove_cv<T>::type>::type type;
};

/// \class is_template_base_of
/// \brief SFINAE test if class is derived from from a base template class.
/// \tparam BASE Base template.
/// \tparam DERIVED Derived class.
template <template<typename...> class BASE, typename DERIVED>
using is_template_base_of = std::integral_constant<
    bool,
    std::is_same<
        typename std::result_of<
            detail::is_template_base_of_helper<BASE, DERIVED>(const DERIVED &)
        >::type,
        typename detail::is_template_base_of_helper<BASE, DERIVED>::yes
    >::value>;


/// \class size_log2
/// \brief Provides an int member value with the log<sub>2</sub> of size of \p T
/// \param T Type from which the size is needed.
template <typename T>
struct size_log2 {
};

/// \cond HIDDEN_SYMBOLS

template <>
struct size_log2<uint8_t> {
    static constexpr int value = 0;
};

template <>
struct size_log2<uint16_t> {
    static constexpr int value = 1;
};

template <>
struct size_log2<uint32_t> {
    static constexpr int value = 2;
};

template <>
struct size_log2<uint64_t> {
    static constexpr int value = 3;
};

/// \endcond

} // namespace cartesi

#endif
