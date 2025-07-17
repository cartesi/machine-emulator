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
///
/// This file provides template classes for SIMD-accelerated hashing operations.
/// It includes specialized hashers for single data items and concatenated data pairs,
/// both utilizing queue-based batching to maximize SIMD efficiency.

#include <cstddef>

#include <boost/container/static_vector.hpp>

#include "compiler-defines.h"
#include "i-hasher.h"
#include "machine-hash.h"

namespace cartesi {

/// \brief SIMD-accelerated data hasher with queue-based batching
/// \tparam hasher_type The underlying SIMD hasher implementation
/// \tparam data_type The type of data to be hashed
/// \tparam MaxQueueSize Maximum number of items that can be queued (defaults to hasher's max lane count)
template <IHasher hasher_type, typename data_type, size_t MaxQueueSize = hasher_type::MAX_LANE_COUNT>
class simd_data_hasher {
    struct data_entry {
        data_type data;           ///< Data to be hashed
        machine_hash_view result; ///< View where the hash result will be stored
    };

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    hasher_type &m_hasher;                                               ///< Underlying hasher instance
    boost::container::static_vector<data_entry, MaxQueueSize> m_queue{}; ///< Queue of pending hash operations

public:
    explicit simd_data_hasher(hasher_type &hasher) : m_hasher(hasher) {}

    /// \brief Enqueues data for hashing
    /// \param data Data to hash
    /// \param result Receives the hash of data
    /// \details If the queue reaches the optimal size, it is automatically flushed.
    void enqueue(data_type data, machine_hash_view result) noexcept {
        m_queue.emplace_back(data_entry{.data = data, .result = result});
        static const size_t optimal_queue_size = std::min(MaxQueueSize, m_hasher.get_optimal_lane_count());
        if (m_queue.size() >= optimal_queue_size) [[unlikely]] { // Queue is full, auto flush it
            flush();
        }
    }

    /// \brief Flushes the queue, clearing it in the process
    void flush() noexcept {
        auto &q = m_queue;
        size_t i = q.size();
        if constexpr (hasher_type::MAX_LANE_COUNT >= 16) {
            while (i >= 16) { // x16 parallel hashing
                i -= 16;
                m_hasher.simd_concat_hash(array2d<data_type, 1, 16>{{{
                                              q[i + 0].data,
                                              q[i + 1].data,
                                              q[i + 2].data,
                                              q[i + 3].data,
                                              q[i + 4].data,
                                              q[i + 5].data,
                                              q[i + 6].data,
                                              q[i + 7].data,
                                              q[i + 8].data,
                                              q[i + 9].data,
                                              q[i + 10].data,
                                              q[i + 11].data,
                                              q[i + 12].data,
                                              q[i + 13].data,
                                              q[i + 14].data,
                                              q[i + 15].data,
                                          }}},
                    std::array<machine_hash_view, 16>{{
                        q[i + 0].result,
                        q[i + 1].result,
                        q[i + 2].result,
                        q[i + 3].result,
                        q[i + 4].result,
                        q[i + 5].result,
                        q[i + 6].result,
                        q[i + 7].result,
                        q[i + 8].result,
                        q[i + 9].result,
                        q[i + 10].result,
                        q[i + 11].result,
                        q[i + 12].result,
                        q[i + 13].result,
                        q[i + 14].result,
                        q[i + 15].result,
                    }});
            }
        }
        while (i >= 8) { // x8 parallel hashing
            i -= 8;
            m_hasher.simd_concat_hash(array2d<data_type, 1, 8>{{{
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
            m_hasher.simd_concat_hash(array2d<data_type, 1, 4>{{{
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
            m_hasher.simd_concat_hash(array2d<data_type, 1, 2>{{{
                                          q[i + 0].data,
                                          q[i + 1].data,
                                      }}},
                std::array<machine_hash_view, 2>{{
                    q[i + 0].result,
                    q[i + 1].result,
                }});
        }
        if (i >= 1) { // x1 scalar hashing
            i -= 1;
            m_hasher.simd_concat_hash(array2d<data_type, 1, 1>{{
                                          {q[i + 0].data},
                                      }},
                std::array<machine_hash_view, 1>{
                    {q[i + 0].result},
                });
        }
        q.clear();
    }
};

/// \brief SIMD-accelerated concatenation hasher with queue-based batching
/// \tparam hasher_type The underlying SIMD hasher implementation
/// \tparam data_type The type of data to be hashed
/// \tparam MaxQueueSize Maximum number of pairs that can be queued (defaults to hasher's max lane count)
template <IHasher hasher_type, typename data_type, size_t MaxQueueSize = hasher_type::MAX_LANE_COUNT>
class simd_concat_hasher {
    struct concat_entry {
        data_type left;           ///< Left data to be concatenated and hashed
        data_type right;          ///< Right data to be concatenated and hashed
        machine_hash_view result; ///< View where the hash result will be stored
    };

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    hasher_type &m_hasher; ///< The underlying SIMD hasher instance
    boost::container::static_vector<concat_entry, MaxQueueSize>
        m_queue{}; ///< Queue of pending concatenation hash operations

public:
    explicit simd_concat_hasher(hasher_type &hasher) : m_hasher(hasher) {}

    /// \brief Enqueues data pair for concat hashing
    /// \param left Left data to hash
    /// \param right Right data to hash
    /// \param result Receives the hash of concatenated data
    /// \details If the queue reaches the optimal size, it is automatically flushed.
    void enqueue(data_type left, data_type right, machine_hash_view result) noexcept {
        m_queue.emplace_back(concat_entry{.left = left, .right = right, .result = result});
        static const size_t optimal_queue_size = std::min(MaxQueueSize, m_hasher.get_optimal_lane_count());
        if (m_queue.size() >= optimal_queue_size) [[unlikely]] { // Queue is full, auto flush it
            flush();
        }
    }

    /// \brief Flushes the queue, clearing it in the process
    void flush() noexcept {
        auto &q = m_queue;
        size_t i = q.size();
        if constexpr (hasher_type::MAX_LANE_COUNT >= 16) {
            while (i >= 16) { // x16 parallel hashing
                i -= 16;
                m_hasher.simd_concat_hash(array2d<data_type, 2, 16>{{
                                              {
                                                  q[i + 0].left,
                                                  q[i + 1].left,
                                                  q[i + 2].left,
                                                  q[i + 3].left,
                                                  q[i + 4].left,
                                                  q[i + 5].left,
                                                  q[i + 6].left,
                                                  q[i + 7].left,
                                                  q[i + 8].left,
                                                  q[i + 9].left,
                                                  q[i + 10].left,
                                                  q[i + 11].left,
                                                  q[i + 12].left,
                                                  q[i + 13].left,
                                                  q[i + 14].left,
                                                  q[i + 15].left,
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
                                                  q[i + 8].right,
                                                  q[i + 9].right,
                                                  q[i + 10].right,
                                                  q[i + 11].right,
                                                  q[i + 12].right,
                                                  q[i + 13].right,
                                                  q[i + 14].right,
                                                  q[i + 15].right,
                                              },
                                          }},
                    std::array<machine_hash_view, 16>{
                        q[i + 0].result,
                        q[i + 1].result,
                        q[i + 2].result,
                        q[i + 3].result,
                        q[i + 4].result,
                        q[i + 5].result,
                        q[i + 6].result,
                        q[i + 7].result,
                        q[i + 8].result,
                        q[i + 9].result,
                        q[i + 10].result,
                        q[i + 11].result,
                        q[i + 12].result,
                        q[i + 13].result,
                        q[i + 14].result,
                        q[i + 15].result,
                    });
            }
        }
        while (i >= 8) { // x8 parallel hashing
            i -= 8;
            m_hasher.simd_concat_hash(array2d<data_type, 2, 8>{{
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
            m_hasher.simd_concat_hash(array2d<data_type, 2, 4>{{
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
            m_hasher.simd_concat_hash(array2d<data_type, 2, 2>{{
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
        if (i >= 1) { // x1 scalar hashing
            i -= 1;
            m_hasher.simd_concat_hash(array2d<data_type, 2, 1>{{
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
