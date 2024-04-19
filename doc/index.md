---
title: Introduction
id: intro
---

The Cartesi Machine is Cartesi's solution for verifiable computation.
It was designed to bring mainstream scalability to dApps and mainstream productivity to dApp developers.

## Scalability

dApps running exclusively on smart contracts face severe constraints on the amount of data they can manipulate and on the complexity of computations they can perform.
These limitations manifest themselves as exorbitant transaction costs and, even if such costs could somehow be overcome, as extremely long computation times.

In comparison, dApps running inside Cartesi Machines can process relatively unlimited amounts of data, and at a pace over 4 orders of magnitude faster.
This is possible because Cartesi Machines run off-chain, free of the overhead imposed by the consensus mechanisms used by blockchains.

In a typical scenario, one of the parties involved in a dApp will execute the Cartesi Machine off-chain and report its results to the blockchain.
Different parties do not need to trust each other because the Cartesi platform includes an automatic dispute mechanism for Cartesi Machines.
All interested parties repeat the computation off-chain and, if their results do not agree, they enter into a dispute, which the mechanism guarantees to be always won by an honest party against any dishonest party.

To enable this dispute mechanism, Cartesi Machines are executed inside a special emulator that has three unique properties:

- Cartesi Machines are _self contained_ &mdash; They run in isolation from any external influence on the computation;
- Cartesi Machines are _reproducible_ &mdash; Two parties performing the same computation always obtain exactly the same results;
- Cartesi Machines are _transparent_ &mdash; They expose their entire state for external inspection.

From the point of view of the blockchain, the disputes require only a tiny fraction of the amount of computation performed by the Cartesi Machine.
Dispute resolution thus becomes an ordinary task and dishonest parties are generally expected to be exposed, which discourages the posting of incorrect results and further increases the efficiency of the platform.

Cartesi Machines allow dApps to take advantage of vastly increased computing capabilities off-chain, while enjoying the same security guarantees offered by code that runs natively as smart contracts.
This is what Cartesi means by scalability.

## Productivity

Scalability is not the only impediment to widespread blockchain adoption.
Another serious limiting factor is the reduced developer productivity.

Modern software development involves the combination of dozens of off-the-shelf software components.
Creating these components took the concerted effort of an active worldwide community over the course of several decades.
They have all been developed and tested using well-established toolchains (programming languages, compilers, linkers, profilers, debuggers, etc.), and rely on multiple services provided by modern operating systems (memory management, multi-tasking, file systems, networking, etc.).

Smart contracts are developed using ad-hoc toolchains, and run directly on top of custom virtual machines, without the support of an underlying operating system.
This arrangement deprives developers of the tools of their trade, severely reduces their expressive power, and consequently decimates their productivity.

In contrast, Cartesi Machines are based on a proven platform: [RISC-V](https://riscv.org/).
RISC-V was born of research in academia at UC Berkeley.
It is now maintained by its own independent foundation.
Unlike many of its academic counterparts, it is important to keep in mind that RISC-V is not a toy architecture.
It is suitable for direct native hardware implementation, which is indeed currently commercialized by a large (and ever-increasing) number of [vendors](https://en.wikipedia.org/wiki/RISC-V#Implementations).
This means that, in the future, Cartesi will not be limited to emulation or binary translation off-chain.
The RISC-V platform is supported by a vibrant community of developers.
Their efforts have produced an extensive software infrastructure, most notably ports of the Linux Operating System and the GNU toolchain.

By moving key parts of their dApp logic to run inside Cartesi Machines, but on top of the Linux Operating System, developers are isolated not only from the limitations and idiosyncrasies of specific blockchains, but also from irrelevant details of the Cartesi Machine architecture itself.
They regain access to all the tools they have come to rely on when writing applications.

This is Cartesi's contribution to empowering dApp developers to express their creativity unimpeded, and to boost their productivity.

## What's in a machine

All the components needed to create and run Cartesi Machines are distributed in the [Emulator SDK](http://www.github.com/cartesi/machine-emulator-sdk).

Cartesi Machines are separated into a processor and a board.
The processor performs the computations, executing the traditional fetch-execute loop while maintaining a variety of registers.
The board defines the surrounding environment with an assortment of memories (ROM, RAM, flash drives, memory ranges) and a number of devices.
Memories and devices are mapped to the 64-bit physical address space of the Cartesi Machine.
The amount of RAM, as well as the number, length, and position of the flash drives and memory ranges in the address space can be chosen according to the needs of each particular application.
The Cartesi Machine emulator is a program that carefully implements the Cartesi Machine architecture so that its executions are reproducible.
It can be built in the `/emulator` directory of the Emulator SDK.

The initialization of a Cartesi Machine loads a ROM image, a RAM image, and a root file-system (as a flash drive) from regular files in the host file-system.
Execution starts from the ROM image, which contains a simple program that creates a description of the machine organization for the Linux kernel.
The ROM image `rom.bin` can be built in the `rom/` directory in the Emulator SDK.
The Linux kernel itself resides in the RAM image `linux.bin`, built in the `kernel/` directory in the Emulator SDK.
After it is done with its own initialization, the Linux kernel cedes control to the `/sbin/init` program in the root file-system.
The root file-system `rootfs.ext2` contains all the data files and programs that make up an embedded Linux distribution.
It can be built in the `fs/` directory in the Emulator SDK.
The components of the target application can reside in the root file-system itself, or in their own, separate file-systems.
The emulator can be instructed to execute whatever command is necessary to start the target application.
For a complete description of the Cartesi Machine architecture and the boot process, see the documentation for [the target perspective](./target/index.md).

There are two distinct modes of operation.
In the first mode, a Cartesi Machine is initialized and tasked to run a target application until the machine _halts_.
Inputs for the target application can be provided as additional flash drives.
Likewise, outputs can be sent to their own flash drives.
(These drives can contain entire file-systems or can contain raw data.)
Outputs are only available to the host after the machine halts.
Once it halts, the machine cannot perform any additional computations.

In the second mode of operation, the target application runs in a loop.
In each iteration, it obtains a request carrying an input, performs any necessary computations to service the request, and produces a number of responses.
After producing each response, the target application asks the machine to _yield_ control back to the host.
The host extracts the response and _resumes_ the machine.
When done with a given input, the target application once again asks the machine to yield control back to the host.
The host then prepares the input for the next request, and _resumes_ the machine so the target application can service the next request in a new iteration of its loop.
Inputs and responses are transferred in special memory ranges (_rollup_ memory ranges).
Whatever state changes happen during the processing of a request will remain in effect when the next request is processed.
Indeed, this is much like a server in which the target application can interact with the outside world.
We say that a Cartesi Machine operating in this mode is a _Rolling Cartesi Machine_.

### Rolling Cartesi Machines and Cartesi Rollups

The stringent demands of reproducibility prevent a Cartesi Machine from communicating _directly_ with the outside world.
Indeed, if two parties were to run the same Cartesi Machine and then disagree on the data each instance independently obtained from a network connection, there would be no way to settle their dispute.
Instead, Rolling Cartesi Machines communicate with the outside world under controlled conditions, through _Cartesi Rollups_.

In a nutshell, Cartesi Rollups uses the blockchain to maintain a public record of requests made to advance the state of a Rolling Cartesi Machine.
Both the order and the inputs carried by these requests are recorded and made available in an indisputable fashion.
Since Cartesi Machines are deterministic, and since the inputs are agreed upon, the state of a Rolling Cartesi Machine can be advanced in a well-defined way, always producing the same set of responses, no matter who runs it.

Advancing the state of a Rolling Cartesi Machine can produce four types of response: _vouchers_, _notices_, _reports_, and
_exceptions_.
Vouchers allow a Rolling Cartesi Machine to interact back with the blockchain.
A voucher issued by the target application may, for example, grant a user the right to withdraw tokens locked into a custodial smart contract.
Notices are used to register noteworthy changes to the state of the target application.
A notice may be issued, for example, announcing the demise of a character in a game.
Disputes over the fact that a voucher or notice has been generated while advancing the state of a Rolling Cartesi Machine can be settled by Cartesi Rollups.
Reports, in contrast, are used to output any data that is irrelevant to the blockchain.
A report may, for example, provide diagnostic information on the reasons why an input has been rejected.
Finally, an exception is used to signal an irrecoverable error encountered by the target application.

It is also possible to inspect the state of a local Rolling Cartesi Machine, without modifying it.
State inspection produces only reports and exceptions.

## Documentation

Cartesi Machines can be seen from 3 different perspectives:

- _The host perspective_ &mdash;
  This is the environment right outside the Cartesi Machine emulator.
  It is most relevant to developers setting up Cartesi Machines, running them, or manipulating their contents.
  It includes the emulator's API in all its flavors: C, C++, Lua, gRPC, and the command-line interface;
- _The target perspective _ &mdash;
  This is the environment inside the Cartesi Machine.
  It encompasses Cartesi's particular flavor of the RISC-V architecture, as well as the organization of the embedded Linux Operating System that runs on top of it.
  It is most relevant to programmers responsible for the dApp components that run off-chain but must be verifiable.
  The cross-compiling toolchain, and the tools used to build the Linux kernel and the embedded Linux root file-systems are also important from this perspective, even though they are used in the host;
- _The blockchain perspective_ &mdash;
  This is the view smart contracts have of Cartesi Machines.
  It consists almost exclusively of the manipulation of cryptographic hashes of the state of Cartesi Machines and parts thereof.
  In particular, using only hash operations, the blockchain can verify assertions concerning the contents of the state, and can obtain the state hash that results from modifications to the state (including the execution of RISC-V instructions).

As with every computer, the level of knowledge required to interact with Cartesi Machines depends on the nature of the application being created.
Simple applications will require target developers to code a few scripts invoking pre-installed software components, require host developers to simply fill out a configuration file specifying the location of the components needed to build a Cartesi Machine, and require blockchain developers to simply instantiate one of the high-level contracts provided by Cartesi.
At the other extreme are the developers working inside Cartesi, who regularly write, build, and deploy custom software components to run in the target, or even change the Linux kernel to support Cartesi-specific devices. Additionally, these developers programmatically control the creation and execution of Cartesi Machines in the host, and must also understand and use the hash-based state manipulation primitives the blockchain needs.

Although Cartesi's goal is to shield platform users from as much complexity as possible, there is value in making information available to the greatest feasible extent. To that end, this documentation of Cartesi Machines aims to provide enough information to cover all 3 perspectives, at all depths of understanding.
