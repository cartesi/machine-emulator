#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

/// \file
/// \brief State access log implementation

#include <cstdint>
#include <vector>
#include <tuple>

#include "merkle-tree.h"
#include "bracket-note.h"

namespace cartesi {

/// \brief Type of state access
enum class access_type {
    read, ///< Read operation
    write ///< Write operation
};

/// \brief Records access to a word in the machine state
struct word_access {
    access_type type{0};             ///< Type of state access
    uint64_t read{0};                ///< Word value before access
    uint64_t written{0};             ///< Word value after access (if writing)
    merkle_tree::proof_type proof{}; ///< Proof of word value before access
};

/// \brief Log of state accesses
class access_log {

    std::vector<word_access> m_accesses{};  ///< List of all accesses
    std::vector<bracket_note> m_brackets{}; ///< Begin/End annotations
    std::vector<std::string> m_notes{};     ///< Per-access annotations

public:

    /// \brief Clear the log
    void clear(void) {
        m_accesses.clear();
        m_notes.clear();
        m_brackets.clear();
    }

    /// \brief Adds a bracket annotation to the log
    /// \param type Bracket type
    /// \param text Annotation contents
    void push_bracket(bracket_type type, const char *text) {
        m_brackets.push_back(bracket_note{type, m_accesses.size(), text});
    }

    /// \brief Adds a new access to the log
    /// \param access Word access
    /// \param text Annotation contents
    void push_access(const word_access &access, const char *text) {
        m_accesses.push_back(access);
        m_notes.push_back(text);
    }

    /// \brief Returns the array of notes
    /// \return Constant reference to array
    const std::vector<std::string> &get_notes(void) const {
        return m_notes;
    }

    /// \brief Returns the array of accesses
    /// \return Constant reference to array
    const std::vector<word_access> &get_accesses(void) const {
        return m_accesses;
    }

    /// \brief Returns the array of brackets
    /// \return Constant reference to array
    const std::vector<bracket_note> &get_brackets(void) const {
        return m_brackets;
    }

};

} // namespace cartesi

#endif
