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
    bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet swiotlb=noforce mtdparts=flash.0:-(root);flash.1:-(foo) -- cat /mnt/foo/bar.txt",
    image_filename = "/opt/cartesi/share/images/rom.bin",
  },
  flash_drive = {
    {
      image_filename = "/opt/cartesi/share/images/rootfs.ext2",
      start = 0x8000000000000000,
      length = 0x5000000,
    },
    {
      image_filename = "foo.ext2",
      start = 0x9000000000000000,
      length = 0x100000,
    },
  },
}
