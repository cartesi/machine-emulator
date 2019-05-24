#ifndef PMA_DEFINES_H
#define PMA_DEFINES_H

#define CLOCK_FREQ             1000000000 ///< 1 GHz frequency is arbitrary
#define DEVICE_TREE_MAX_SIZE   0x10000 ///< Device tree buffer size
#define PMA_HTIF_START_DEF     0x40008000 ///< HTIF base address (to_host)
#define PMA_RAM_START_DEF      0x80000000 ///< RAM start address
#define PMA_ROM_LENGTH_DEF     0xF000 ///< ROM length in bytes
#define PMA_ROM_START_DEF      0x1000 ///< ROM start address
#define PMA_START_DEF          0x800 ///< PMA array start address
#define PMA_EXT_LENGTH_DEF     0x1000 ///< PMA Extension max length in bytes
#define PMA_EXT_START_DEF      (PMA_ROM_START_DEF + PMA_ROM_LENGTH_DEF - PMA_EXT_LENGTH_DEF) ///< PMA extension start address

// helper for using UINT64_C with defines
#define EXPAND_UINT64_C(a) UINT64_C(a)

#endif /* end of include guard: PMA_DEFINES_H */
