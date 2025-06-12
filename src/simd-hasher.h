// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef SIMD_HASHER_H
#define SIMD_HASHER_H

/// \file
/// \brief SIMD hasher interface

#include <boost/container/static_vector.hpp>

#include "compiler-defines.h"
#include "i-hasher.h"
#include "machine-hash.h"

namespace cartesi {

constexpr int SIMD_HASHER_LANE_COUNT = 8; ///< Number of SIMD hasher lanes

template <typename hasher_type, typename data_type, size_t QueueSize = SIMD_HASHER_LANE_COUNT>
class simd_data_hasher {
    struct data_entry {
        data_type data;
        machine_hash_view result;
    };

    hasher_type m_hasher;
    boost::container::static_vector<data_entry, QueueSize> m_queue{};

public:
    /// \brief Enqueues data for hashing
    /// \param data data_typeata to hash
    /// \param result Receives the hash of data
    void enqueue(data_type data, machine_hash_view result) {
        m_queue.emplace_back(data_entry{.data = data, .result = result});
        if (unlikely(m_queue.size() == m_queue.capacity())) { // Queue is full, auto flush it
            flush();
        }
    }

    /// \brief Flushes the queue, clearing it in the process
    void flush() noexcept {
        auto &q = m_queue;
        size_t i = q.size();
        while (i >= 8) { // x8 parallel hashing
            i -= 8;
            m_hasher.parallel_concat_hash(array2d<data_type, 1, 8>{{{
                                              q[i + 0].data,
                                              q[i + 1].data,
                                              q[i + 2].data,
                                              q[i + 3].data,
                                              q[i + 4].data,
                                              q[i + 5].data,
                                              q[i + 6].data,
                                              q[i + 7].data,
                                          }}},
                std::array<machine_hash_view, 8>{{
                    q[i + 0].result,
                    q[i + 1].result,
                    q[i + 2].result,
                    q[i + 3].result,
                    q[i + 4].result,
                    q[i + 5].result,
                    q[i + 6].result,
                    q[i + 7].result,
                }});
        }
        if (i >= 4) { // x4 parallel hashing
            i -= 4;
            m_hasher.parallel_concat_hash(array2d<data_type, 1, 4>{{{
                                              q[i + 0].data,
                                              q[i + 1].data,
                                              q[i + 2].data,
                                              q[i + 3].data,
                                          }}},
                std::array<machine_hash_view, 4>{{
                    q[i + 0].result,
                    q[i + 1].result,
                    q[i + 2].result,
                    q[i + 3].result,
                }});
        }
        if (i >= 2) { // x2 parallel hashing
            i -= 2;
            m_hasher.parallel_concat_hash(array2d<data_type, 1, 2>{{{
                                              q[i + 0].data,
                                              q[i + 1].data,
                                          }}},
                std::array<machine_hash_view, 2>{{
                    q[i + 0].result,
                    q[i + 1].result,
                }});
        }
        if (i >= 1) { // x1 hashing
            i -= 1;
            m_hasher.parallel_concat_hash(array2d<data_type, 1, 1>{{
                                              {q[i + 0].data},
                                          }},
                std::array<machine_hash_view, 1>{
                    {q[i + 0].result},
                });
        }
        q.clear();
    }
};

template <typename hasher_type, typename data_type, size_t QueueSize = SIMD_HASHER_LANE_COUNT>
class simd_concat_hasher {
    struct concat_entry {
        data_type left;
        data_type right;
        machine_hash_view result;
    };

    hasher_type m_hasher;
    boost::container::static_vector<concat_entry, QueueSize> m_queue{};

public:
    /// \brief Enqueues data for concat hashing
    /// \param left Left data to hash
    /// \param right Left data to hash
    /// \param result Receives the hash of data
    void enqueue(data_type left, data_type right, machine_hash_view result) {
        m_queue.emplace_back(concat_entry{.left = left, .right = right, .result = result});
        if (unlikely(m_queue.size() == m_queue.capacity())) { // Queue is full, auto flush it
            flush();
        }
    }
    /// \brief Flushes the queue, clearing it in the process
    void flush() noexcept {
        auto &q = m_queue;
        size_t i = q.size();
        while (i >= 8) { // x8 parallel hashing
            i -= 8;
            m_hasher.parallel_concat_hash(array2d<data_type, 2, 8>{{
                                              {
                                                  q[i + 0].left,
                                                  q[i + 1].left,
                                                  q[i + 2].left,
                                                  q[i + 3].left,
                                                  q[i + 4].left,
                                                  q[i + 5].left,
                                                  q[i + 6].left,
                                                  q[i + 7].left,
                                              },
                                              {
                                                  q[i + 0].right,
                                                  q[i + 1].right,
                                                  q[i + 2].right,
                                                  q[i + 3].right,
                                                  q[i + 4].right,
                                                  q[i + 5].right,
                                                  q[i + 6].right,
                                                  q[i + 7].right,
                                              },
                                          }},
                std::array<machine_hash_view, 8>{
                    q[i + 0].result,
                    q[i + 1].result,
                    q[i + 2].result,
                    q[i + 3].result,
                    q[i + 4].result,
                    q[i + 5].result,
                    q[i + 6].result,
                    q[i + 7].result,
                });
        }
        if (i >= 4) { // x4 parallel hashing
            i -= 4;
            m_hasher.parallel_concat_hash(array2d<data_type, 2, 4>{{
                                              {
                                                  q[i + 0].left,
                                                  q[i + 1].left,
                                                  q[i + 2].left,
                                                  q[i + 3].left,
                                              },
                                              {
                                                  q[i + 0].right,
                                                  q[i + 1].right,
                                                  q[i + 2].right,
                                                  q[i + 3].right,
                                              },
                                          }},
                std::array<machine_hash_view, 4>{
                    q[i + 0].result,
                    q[i + 1].result,
                    q[i + 2].result,
                    q[i + 3].result,
                });
        }
        if (i >= 2) { // x2 parallel hashing
            i -= 2;
            m_hasher.parallel_concat_hash(array2d<data_type, 2, 2>{{
                                              {
                                                  q[i + 0].left,
                                                  q[i + 1].left,
                                              },
                                              {
                                                  q[i + 0].right,
                                                  q[i + 1].right,
                                              },
                                          }},
                std::array<machine_hash_view, 2>{
                    q[i + 0].result,
                    q[i + 1].result,
                });
        }
        if (i >= 1) { // x1 parallel hashing
            i -= 1;
            m_hasher.parallel_concat_hash(array2d<data_type, 2, 1>{{
                                              {q[i + 0].left},
                                              {q[i + 0].right},
                                          }},
                std::array<machine_hash_view, 1>{{
                    q[i + 0].result,
                }});
        }
        q.clear();
    }
};

} // namespace cartesi

#endif // SIMD_HASHER_H
