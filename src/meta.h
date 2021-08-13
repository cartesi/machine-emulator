// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef META_H
#define META_H

#include <cinttypes>
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
template <template <typename...> class BASE, typename DERIVED>
struct is_template_base_of_helper {
    struct no {};
    struct yes {};
    no operator()(...);
    template <typename... T>
    yes operator()(const BASE<T...> &);
};
} // namespace detail

/// \class remove_cvref
/// \brief Provides a member typedef type with reference and topmost cv-qualifiers removed.
/// \note (This is directly available in C++20.)
template <typename T>
struct remove_cvref {
    using type = typename std::remove_reference<typename std::remove_cv<T>::type>::type;
};

/// \class is_template_base_of
/// \brief SFINAE test if class is derived from from a base template class.
/// \tparam BASE Base template.
/// \tparam DERIVED Derived class.
template <template <typename...> class BASE, typename DERIVED>
using is_template_base_of = std::integral_constant<bool,
    std::is_same<typename std::result_of<detail::is_template_base_of_helper<BASE, DERIVED>(const DERIVED &)>::type,
        typename detail::is_template_base_of_helper<BASE, DERIVED>::yes>::value>;

/// \class log2_size
/// \brief Provides an int member value with the log<sub>2</sub> of size of \p T
/// \param T Type from which the size is needed.
template <typename T>
struct log2_size {};

/// \cond HIDDEN_SYMBOLS

template <>
struct log2_size<uint8_t> {
    static constexpr int value = 0;
};

template <>
struct log2_size<uint16_t> {
    static constexpr int value = 1;
};

template <>
struct log2_size<uint32_t> {
    static constexpr int value = 2;
};

template <>
struct log2_size<uint64_t> {
    static constexpr int value = 3;
};

/// \endcond

} // namespace cartesi

#endif
