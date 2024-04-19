return {
  processor = {
    mvendorid = 0x6361727465736920, -- cartesi.machine.MVENDORID
    mimpid = 0x1, -- cartesi.machine.MIMPID
    marchid = -1, -- cartesi.machine.MARCHID
  },
  ram = {
    image_filename = "/opt/cartesi/share/images/linux.bin",
    length = 0x4000000,
  },
  rom = {
    image_filename = "/opt/cartesi/share/images/rom.bin",
    bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet swiotlb=noforce mtdparts=flash.0:-(root) -- for i in $(seq 0 5 1000); do yield automatic progress $i; done",
  },
  htif = {
    yield_automatic = true,
  },
  flash_drive = {
    {
      image_filename = "/opt/cartesi/share/images/rootfs.ext2",
      start = 0x8000000000000000,
      length = 0x5000000,
    },
  },
}
