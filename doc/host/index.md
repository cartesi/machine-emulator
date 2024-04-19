---
title: Overview

---

Cartesi's reference off-chain implementation of Cartesi Machines is based on software emulation.
The emulator is written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilities.
The `emulator/` directory in the [Emulator SDK](https://github.com/cartesi/machine-emulator-sdk) can be used to build and install the Cartesi Machine emulator.
It is written as a C++ class, but can be accessed in a variety of different ways.

When linked to a C++ application, the emulator can be controlled directly via the interface of the `cartesi::machine` class.
C applications can control the emulator in a similar way, by means of a matching C API.
The emulator can also be accessed from the Lua programming language, via a `cartesi` module that exposes a `cartesi.machine` interface to Lua programs.
Additionally, Cartesi provides a [gRPC](https://grpc.io) server that can run a Cartesi Machine instance that is controlled remotely.
Finally, there is a command-line utility (written in Lua) that can configure and run Cartesi Machines for rapid prototyping.
The C, C++, Lua APIs as well as the command-line utility can seamlessly instantiate local emulators or connect to remote gRPC servers.

The documentation starts from the command-line utility, `cartesi-machine`.
This utility is used for most prototyping tasks.
The documentation then covers the Lua interface of `cartesi.machine`.
The C/C++/gRPC interfaces are very similar, and are covered only within their reference manuals.

## Machine playground

The setup of a new development environment is often a time-consuming task.
This is particularly true in case of cross-development environments (i.e., when the development happens in a host platform but software runs in a different target platform).
With this in mind, the Cartesi team provides the `cartesi/playground` Docker image for use while reading this documentation.
The Docker image enables immediate experimentation with Cartesi Machines.
It comes with a pre-built emulator and Lua interpreter accessible within the command-line, as well as a pre-built ROM image, RAM image, and root file-system.
It also comes with the cross-compiler for the RISC-V architecture on which the Cartesi Machine is based.

To enter the playground, open a terminal, download the Docker image from Cartesi's repository, and run it adequately mapping the current user and group information, as well as making the host's current directory available inside the container:

```bash
docker pull cartesi/playground:0.5.0
```

```bash
docker run -it --rm -h playground \
    -e USER=$(id -u -n) \
    -e GROUP=$(id -g -n) \
    -e UID=$(id -u) \
    -e GID=$(id -g) \
    -v `pwd`:/home/$(id -u -n) \
    -w /home/$(id -u -n) \
    cartesi/playground:0.5.0 /bin/bash
```

Once inside, you can execute the `cartesi-machine` utility as follows:

```
cartesi-machine --help
```

```
%machine.host.overview.help
```

A final check can also be performed to verify if the contents inside the container are as expected:

```
sha256sum /opt/cartesi/share/images/linux.bin
```

```
%machine.host.overview.sha256-linux
```

```
sha256sum /opt/cartesi/share/images/rom.bin
```

```
%machine.host.overview.sha256-rom
```

```
sha256sum /opt/cartesi/share/images/rootfs.ext2
```

```
%machine.host.overview.sha256-rootfs
```

Note that, if the hashes of the files you are using do not match the ones above, then when you attempt to replicate the examples in the documentation, you will obtain different hashes.
Moreover, the cycle counts and outputs may also differ.
