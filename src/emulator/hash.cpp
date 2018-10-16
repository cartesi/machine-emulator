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
