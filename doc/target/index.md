---
title: Overview
---

The goal of the target perspective is to serve both target application-developers and target system-developers.
The documentation therefore starts from the familiar Linux environment that runs inside Cartesi Machines.
This is the abstraction level at which target application-developers interact with Cartesi Machines.
The documentation then moves towards the system architecture implemented by Cartesi Machines, including Cartesi-specific extensions to the RISC-V architecture.
This is what surrounds the Linux environment, and is the abstraction level at which target system-developers work.

This is, of course, not the most natural order for presenting the material.
After all, running the embedded Linux environment experienced by application-developers is only possible after successful initialization of the Linux kernel, which in turn depends on knowledge of the system architecture.
However, presenting the material in this order would quickly alienate application developers.
Since there are many more application developers than system developers, we cater to the former.
