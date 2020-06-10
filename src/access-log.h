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
    write, ///< Write operation
};

/// \brief Records access to a word in the machine state
struct word_access {
    access_type type{0};             ///< Type of state access
    uint64_t address;                ///< Address of access
    uint64_t read{0};                ///< Word value before access
    uint64_t written{0};             ///< Word value after access (if writing)
    merkle_tree::proof_type proof{}; ///< Proof of word value before access
};

/// \brief Log of state accesses
class access_log {
public:

    /// \brief Type of access log
    class type {
        bool m_proofs; ///< Includes proofs
        bool m_annotations; ///< Includes annotations
    public:

        /// \brief Default constructur
        /// \param proofs Include proofs
        /// \param annotations Include annotations (default false)
        explicit type(bool proofs, bool annotations = false):
            m_proofs(proofs),
            m_annotations(annotations) {
            ;
        }

        /// \brief Returns whether log includes proofs
        bool has_proofs(void) const {
            return m_proofs;
        }

        /// \brief Returns whether log includes annotations
        bool has_annotations(void) const {
            return m_annotations;
        }
    };

private:

    std::vector<word_access> m_accesses{};  ///< List of all accesses
    std::vector<bracket_note> m_brackets{}; ///< Begin/End annotations
    std::vector<std::string> m_notes{};     ///< Per-access annotations
    type m_log_type;                        ///< Log type

public:

    explicit access_log(type log_type): m_log_type(log_type) {
        ;
    }

    template <typename ACCESSES, typename BRACKETS, typename NOTES>
    access_log(ACCESSES &&accesses, BRACKETS &&brackets, NOTES &&notes,
        type log_type):
        m_accesses(std::forward<ACCESSES>(accesses)),
        m_brackets(std::forward<BRACKETS>(brackets)),
        m_notes(std::forward<NOTES>(notes)),
        m_log_type(log_type) {
            ;
    }

    /// \brief Clear the log
    void clear(void) {
        m_accesses.clear();
        m_notes.clear();
        m_brackets.clear();
    }

    /// \brief Adds a bracket annotation to the log (if the log type includes annotations)
    /// \param type Bracket type
    /// \param text Annotation contents
    void push_bracket(bracket_type type, const char *text) {
        if (m_log_type.has_annotations())
            m_brackets.push_back(bracket_note{type, m_accesses.size(), text});
    }

    /// \brief Adds a new access to the log
    /// \param access Word access
    /// \param text Annotation contents (added if the log type includes annotations)
    void push_access(const word_access &access, const char *text) {
        m_accesses.push_back(access);
        if (m_log_type.has_annotations())
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

    /// \brief Returns the log type
    /// \return Log type
    type get_log_type(void) const {
        return m_log_type;
    }

};

} // namespace cartesi

#endif
