#!/bin/sh

./riscv-qemu/bin/qemu-system-riscv64 \
        -nographic -machine virt -kernel kernel.elf -snapshot \
        -drive file=rootfs.bin,format=raw,id=hd0 \
        -device virtio-blk-device,drive=hd0 \
        -append "console=hvc0 rootfstype=ext2 root=/dev/vda rw"
