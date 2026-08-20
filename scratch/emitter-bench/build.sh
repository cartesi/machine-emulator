#!/bin/sh -e
# Builds the three emitter-rate microbenchmarks. Run from this directory.
# rvjit-bench links the prebuilt RVVM objects from /private/tmp/rvvm-source.

M=$(cd ../.. && pwd)
R=/private/tmp/rvvm-source
O=$R/release.darwin.arm64/obj/src

cc -O2 -I$R/include -I$R/src -I$R/src/util -I$R/src/rvjit \
    -DUSE_JIT=1 -DUSE_RV64=1 -DUSE_RV32=1 -DUSE_NO_LIBATOMIC=1 -DRVVM_VERSION='"bench"' \
    rvjit-bench.c \
    $O/rvjit/rvjit.o $O/rvjit/rvjit_emit.o \
    $O/util/utils.o $O/util/hashmap.o $O/util/vma_ops.o $O/util/vector.o \
    $O/util/blk_io.o $O/util/rvtimer.o $O/util/locking.o $O/util/threading.o \
    $O/util/stacktrace.o $O/util/dlib.o \
    -o rvjit-bench

cc -O2 -I$M/third-party/downloads/lightning/include -I$M/third-party/lightning/include \
    lightning-bench.c $M/third-party/downloads/lightning/lib/.libs/liblightning.a \
    -o lightning-bench

cc -O2 copypatch-bench.c -o copypatch-bench
