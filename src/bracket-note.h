#ifndef BRACKET_NOTE_H
#define BRACKET_NOTE_H

/// \file
/// \brief Bracket annotation for access log

namespace cartesi {

/// \brief Bracket type
enum class bracket_type {
    begin,    ///< Start of scope
    end,      ///< End of scope
    invalid   ///< Invalid
};

/// \brief Bracket note
struct bracket_note {
    bracket_type type{bracket_type::invalid}; ///< Bracket type
    size_t where{0};                          ///< Where it points to in the log
    std::string text{};                       ///< Note text
};

} // namespace cartesi

#endif
