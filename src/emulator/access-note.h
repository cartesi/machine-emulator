#ifndef ACCESS_NOTE_H
#define ACCESS_NOTE_H

/// \file
/// \brief Annotation for access log

namespace cartesi {

/// \brief Note type
enum class note_type {
    begin, ///< Start of scope
    end,   ///< End of scope
    point  ///< Point-wise annotation
};

/// \brief Access note
struct access_note {
    note_type type{note_type::point}; ///< Note type
    size_t where{0};                  ///< Where it points to in the log
    std::string text{};               ///< Note text
};

} // namespace cartesi

#endif
