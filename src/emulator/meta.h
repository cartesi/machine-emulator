#ifndef META_H
#define META_H

#include <type_traits>

/// \file
/// \brief Meta-programming helper functions

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
/// \brief SFINAE test if class inherites from a template class.
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

#endif
