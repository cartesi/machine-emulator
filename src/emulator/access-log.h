#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

/// \file
/// \brief State access log implementation

#include <cstdint>
#include <vector>
#include <tuple>

#include "merkle-tree.h"
#include "access-note.h"

/// \brief Type of state access
enum class access_type {
    read, ///< Read operation
    write ///< Write operation
};

/// \brief Records access to a word in the machine state
struct word_access {
    access_type type;        ///< Type of state access
    uint64_t read;           ///< Word value before access
    uint64_t written;        ///< Word value after access (if writing)
    std::string text;        ///< Text describing purpose of access
    merkle_tree::proof_type proof; ///< Proof of word value before access
};

/// \brief Log of state accesses
struct access_log {
    std::vector<word_access> accesses; ///< List of all accesses
    std::vector<access_note> notes;    ///< Annotations

    /// \brief Clear the log
    void clear(void) {
        accesses.clear();
        notes.clear();
    }

    /// \brief Adds an annotation to the log.
    /// \param type Annotation type.
    /// \param text Annotation contents.
    void annotate(note_type type, const char *text) {
        notes.push_back(access_note{type, accesses.size(), text});
    }
};

#endif
