#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <cinttypes>
#include <vector>

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
    std::cerr << std::hex << std::setfill('0') << std::setw(2);
    for (unsigned i = 0; i < 32; ++i) {
        unsigned b = hash[i];
        std::cerr << b;
    }
    std::cerr << '\n';
    std::cerr.flags(f);
}

int main(void) {
    CryptoPP::Keccak_256 kc;
    uint8_t a[] = {0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t hash_a[32];
    uint8_t b[] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint8_t hash_b[32];
    uint8_t hash_hash_a_hash_b[32];
    kc.Restart();
    kc.Update(a, sizeof(a));
    kc.Final(hash_a);
    dump(hash_a);
    kc.Restart();
    kc.Update(b, sizeof(b));
    kc.Final(hash_b);
    dump(hash_b);
    kc.Restart();
    kc.Update(hash_a, sizeof(a));
    kc.Update(hash_b, sizeof(b));
    kc.Final(hash_hash_a_hash_b);
    dump(hash_hash_a_hash_b);
    return 0;
}
