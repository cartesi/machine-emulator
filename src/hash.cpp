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

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <cinttypes>
#include <vector>

#include "cryptopp-keccak-256-hasher.h"
#include "xkcp-keccak-256-hasher.h"
#include "merkle-tree.h"

static int prefix(const char *pre, const char *str) {
    return strncmp(pre, str, strlen(pre)) == 0;
}

#if 0
int main(int argc, char *argv[]) {
    merkle_tree tree;
    uint8_t buf[4096];
    uint64_t base = 0;
    CryptoPP::Keccak_256 kc;
    int end = 0;
    for (int i = 1; i < argc; i++) {
        if (prefix("--base=", argv[i])) {
            if (sscanf(argv[i], "--base=0x%" SCNx64 "%n", &base, &end) == 1 &&
                argv[i][end] == 0) {
                std::cerr << "Base set to 0x" << std::hex << base << std::dec << '\n';
            } else if (sscanf(argv[i], "--base=%" SCNu64 "%n", &base, &end) == 1 &&
                argv[i][end] == 0) {
                std::cerr << "Base set to " << base << '\n';
            } else {
                std::cerr << "Invalid base '" << argv[i] << "'\n";
                break;
            }
        } else if (strcmp("--root-hash", argv[i]) == 0) {
            merkle_tree::keccak_256_hash hash;
            tree.get_merkle_tree_root_hash(hash);
            auto flags = std::cout.flags();
            std::cout << std::hex << std::setfill('0') << std::setw(2);
            std::copy(hash.begin(), hash.end(),
                std::ostream_iterator<int>(std::cout));
            std::cout << '\n';
            std::cout.flags(flags);
        } else {
            FILE *fp = fopen(argv[i], "rb");
            if (!fp) {
                std::cerr << "Unable to open file '" << argv[i] << "'\n";
                break;
            }
            fseek(fp, 0, SEEK_END);
            auto n = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            std::cerr << "Processing " << n << " bytes\n";
            tree.begin_update(kc);
            for ( ; ; ) {
                auto got = fread(buf, 1, sizeof(buf), fp);
                if (got > 0) {
                    memset(buf+got, 0, sizeof(buf)-got);
                    tree.update_page(kc, base, buf);
                    base += sizeof(buf);
                } else {
                    base = 0;
                    fclose(fp);
                    break;
                }
            }
            tree.end_update(kc);
        }
    }

    return 0;
}
#endif

static void dump(const uint8_t *hash) {
    auto f = std::cerr.flags();
    for (unsigned i = 0; i < 32; ++i) {
        unsigned b = hash[i];
        std::cerr << std::hex << std::setfill('0') << std::setw(2) << b;
    }
    std::cerr << '\n';
    std::cerr.flags(f);
}

int main(void) {
    uint8_t a[] = {0, 0, 0, 0, 0, 0, 0, 1};
    using C = cartesi::cryptopp_keccak_256_hasher;
    C HC;
    C::hash_type hc;
    HC.begin();
    HC.add_data(a, sizeof(a));
    HC.end(hc);
    dump(hc.data());
    using X = cartesi::xkcp_keccak_256_hasher;
    X HX;
    X::hash_type hx;
    HX.begin();
    HX.add_data(a, sizeof(a));
    HX.end(hx);
    dump(hx.data());
    return 0;
}
