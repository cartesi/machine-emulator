# Hypervisor usage instructions

The hypervisor feature is still at a highly experimental stage.

In this document, we will use the term _host_ (or _host machine_) to address a cartesi machine instance that hosts a hypervisor, and the term _guest_ (or _guest machine_, or _virtual machine_) to address a machine running inside a hypervisor.

## Quick start

### Prepare the artifacts

To test the hypervisor without building everything from scratch, you could download the rootfs and the kernel from google drive:
- [rootfs](https://drive.google.com/file/d/1Hy9VibEf6SZU4qtqqb8n5CzHq-eN7uO7/view?usp=share_link)
- [kernel](https://drive.google.com/file/d/1Wc9yAJLpxxg14aFDPvYcQQmrA7JPt1ZC/view?usp=share_link)

### Build the emulator with a hypervisor support

To build the emulator with hypervisor support you have to use the `hypervisor` [branch](https://github.com/cartesi-corp/machine-emulator/tree/feature/hypervisor) and follow the [regular build instructions](https://github.com/cartesi-corp/machine-emulator/blob/develop/README.md). After you execute `make install`, the emulator with hypervisor support will be installed in the `/opt/cartesi-hp` folder.

### Run the virtual machine

First of all, you have to make sure that you are using the correct emulator version. There is a special `set_lua_env_hp.sh` script for this in the repo root you may want to use. The command `source set_lua_env_hp.sh` will do the job.

#### Booting a host

To launch a new cartesi machine instance, use the following command:

```bash
/opt/cartesi-hp/bin/cartesi-machine \
    --ram-image=/path/to/downloaded/opensbi.bin \
    --rom-image=/opt/cartesi/share/images/rom-v0.13.0.bin \
    --ram-length=1024Mi \
    --flash-drive=label:root,filename:/path/to/downloaded/rootfs-v0.15.0-dirty.ext2 \
    -i -- "/bin/sh"
```

This will give you a command prompt inside a host.

#### Booting a guest

All the hypervisor stuff you need is located inside the `/hp` folder on the host. To execute a virtual machine follow these steps:
1. load the `kvm` kernel module: `cd /hp && insmod kvm.ko`;
1. start the virtual machine with the provided script: `./start_machine.sh`.

At this point, you should get a command prompt inside a virtual machine.

### Looking around

#### Testing network

Inside both host and guest file systems you will find a `sender.py` and a `receiver.py` Python scripts. For the host, the scripts are located inside the `/hp` folder; for the guest look for them inside the `/opt` folder. These scripts could be used to test a network connection between the host and the guest.
    - `receiver.py <address to listen> <port to listen>`: listens for the incoming data on the given address, and prints the data as soon as it is received;
    - `sender.py <address to use> <port to use> <data>`: sends the `data` to the given address.

#### Guest startup script

The `init` process inside the guest executes an `/opt/start.sh` script. You may want to modify this script to customize the guest startup behavior.

#### Modifying a guest file system

At some point, you may want to persist changes in the guest file system. The corresponding `.ext2` file is located inside the host file system: `/hp/rootfs-virt.ext2`. You can mount this file and make any changes to the corresponding file system:

```bash
$ sudo mount /path/to/downloaded/rootfs-v0.15.0-dirty.ext2 /mnt
$ sudo mount /mnt/hp/rootfs-virt.ext2 /mnt-virt
...
$ sudo umount /mnt-virt
$ sudo umount /mnt
```

## Bootstrapping from scratch

### Build the emulator with a hypervisor support

Please, refer to [this section](https://github.com/cartesi-corp/machine-emulator/blob/hypervisor/hypervisor.md#build-the-emulator-with-a-hypervisor-support).

### Build a kernel

The hypervisor extension support for the RISC-V architecture is available only in the Linux kernel v6.0.9+. So, the first step you have to do is to clone the `cartesi-corp/linux` repo and checkout the corresponding branch:

```bash
$ git clone git@github.com:cartesi-corp/linux.git
$ git checkout update/linux-6.0.9-ctsi-y
```

To build the kernel you have to use the [correct config](https://github.com/cartesi-corp/image-kernel/blob/hypervisor-config/configs/kvm-linux-config). Do not forget to copy it to your Linux kernel repo root directory.

You also have to use `opensbi` to boot the kernel to have the compatible SBI interface version:

```bash
$ git clone git@github.com:cartesi-corp/opensbi.git
$ git checkout feature/cartesi-legacy
```

Now you are ready to build a kernel using the Cartesi toolchain:

```bash
$ docker run -v /path/to/linux:/linux -v /path/to/opensbi:/opensbi -it cartesicorp/toolchain:0.14.0
$ export ARCH=riscv; export CROSS_COMPILE=/opt/riscv/riscv64-cartesi-linux-gnu/bin/riscv64-cartesi-linux-gnu-; make Image
$ export FW_PAYLOAD_PATH=/linux/arch/riscv/boot/Image; export PLATFORM=cartesi; make
```

You should have three files as output:
1. host kernel: `/path/to/opensbi/platform/cartesi/firmware/fw_payload.bin`;
1. guest kernel: `/path/to/linux/arch/riscv/boot/Image`;
1. kvm kernel module: `/path/to/linux/arch/riscv/kvm/kvm.ko`.

### Build root file systems

To be able to work with a hypervisor, you need root user permissions. The current root file system build does not provide this capability, so you have to use the version from the `hypervisor` [branch](https://github.com/cartesi-corp/image-rootfs/tree/hypervisor) to fix this. Other aspects are not different from the [regular build process](https://github.com/cartesi-corp/image-rootfs/blob/develop/README.md). Just keep in mind that after the host rootfs is compiled, you will have to copy the hypervisor-related files to it (KVM kernel module, lkvm tool, guest kernel, guest root file system, and any supporting scripts), so there should be enough free space.

The same rootfs build may be used both for the host and the guest.

### Build the LKVM tool

To run a virtual machine [we need](https://github.com/kvm-riscv/howto/wiki/KVM-RISCV64-on-Spike#4-add-libfdt-library-to-cross_compile-sysroot-directory) lkvm tool. Here are the steps to build it (should be executed inside the toolchain container):

```bash
$ git clone git://git.kernel.org/pub/scm/utils/dtc/dtc.git
$ cd dtc
$ export ARCH=riscv; export CROSS_COMPILE=/opt/riscv/riscv64-cartesi-linux-gnu/bin/riscv64-cartesi-linux-gnu-; export CC="${CROSS_COMPILE}gcc -mabi=lp64d -march=rv64gc"
$ SYSROOT=$($CC -print-sysroot)
$ make libfdt
$ make NO_PYTHON=1 NO_YAML=1 DESTDIR=$SYSROOT PREFIX=/usr LIBDIR=/usr/lib64/lp64d install-lib install-includes
$ cd ..
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git; cd kvmtool; make lkvm-static
$ ${CROSS_COMPILE}strip lkvm-static
```

The above commands will create `kvmtool/lkvm-static` that you need to copy to your host root file system.
