#ifndef DEVICE_TREE_H
#define DEVICE_TREE_H

#include <cstdint>

// Foward declaration
struct pma_ext_hdr;

int build_device_tree(struct pma *pma, struct pma_ext_hdr *pma_ext, uint64_t misa, void *buf, uint64_t buflen);

#endif /* DEVICE_TREE_H */
