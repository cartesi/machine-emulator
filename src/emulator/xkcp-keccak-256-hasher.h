#ifndef XKCP_KECCAK_256_HASHER_H
#define XKCP_KECCAK_256_HASHER_H

extern "C" {
#include <KeccakSpongeWidth1600.h>
}

#include "i-hasher.h"

namespace cartesi {

class xkcp_keccak_256_hasher final:
    public i_hasher<xkcp_keccak_256_hasher, 32> {

    KeccakWidth1600_SpongeInstance m_state;

    /// \brief No copy constructor
    xkcp_keccak_256_hasher(const xkcp_keccak_256_hasher &) = delete;
    /// \brief No move constructor
    xkcp_keccak_256_hasher(xkcp_keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    xkcp_keccak_256_hasher& operator=(const xkcp_keccak_256_hasher &) = delete;
    /// \brief No move assignment
    xkcp_keccak_256_hasher& operator=(xkcp_keccak_256_hasher &&) = delete;

friend i_hasher<xkcp_keccak_256_hasher, 32>;

    void do_begin(void) {
        KeccakWidth1600_SpongeInitialize(&m_state, 1088, 512);
    }

    void do_add_data(const unsigned char *data, size_t length) {
        KeccakWidth1600_SpongeAbsorb(&m_state, data, length);
    }

    void do_end(hash_type &hash) {
        KeccakWidth1600_SpongeAbsorbLastFewBits(&m_state, 1);
        KeccakWidth1600_SpongeSqueeze(&m_state, hash.data(), hash.size());
    }

public:
    /// \brief Default constructor
    xkcp_keccak_256_hasher(void) = default;
};

} // namespace cartesi

#endif
