#include <stddef.h>

#include "util.h"
#include "device-tree.h"


extern "C" void *rom_init(struct pma *pma, struct pma_ext_hdr *pma_ext, void *fdtbuf, uint64_t buflen, uint64_t misa)
{
	// Check invalid values and if misa XLEN is 64bit
	if (pma == NULL || pma_ext == NULL || fdtbuf == NULL || buflen == 0 || !(misa & (1UL<<63)))
		return NULL;

	if (build_device_tree(pma, pma_ext, misa, fdtbuf, buflen) < 0)
		return NULL;

	return fdtbuf;
}
