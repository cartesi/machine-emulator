#!/usr/bin/env python3
"""Verify the committed cross-emulator Linux boot artifacts."""

import hashlib
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGES = HERE / "images"
KERNEL_OFFSET = 2 * 1024 * 1024
ROOTFS = HERE / "rootfs-bench.ext2"
ROOTFS_HASH = "3f6ad0dba2a74d62792794b411dd0791fae194fdf639512b7c9feddb1829eee9"
STRESS_NG = HERE / "guest/stress-ng-musl"
STRESS_NG_HASH = "26caa5259058a82388e537d18d6ac8afee8e0bbb56ddcfd2a13e79e05e508608"

EXPECTED = {
    "cartesi/linux.bin": (17545256, "551ed4dae2b82ed59b4055f18d525a77f5ee35605acbf1238ff83e0cf9bfc3f1"),
    "qemu/Image": (15448096, "c570a15a4cd484088e72f8f28bf74e404888904ed00768433a68b33f10c8c4c0"),
    "rvvm/linux.bin": (17545248, "c2370b05b683d511851279c5c3f637873a334898597db283c11a2da413bffa13"),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_images(require_rootfs=False):
    contents = {}
    for name, (expected_size, expected_hash) in EXPECTED.items():
        data = (IMAGES / name).read_bytes()
        actual = (len(data), sha256(data))
        expected = (expected_size, expected_hash)
        assert actual == expected, f"{name}: expected {expected}, got {actual}"
        contents[name] = data
        print(f"{actual[1]}  images/{name}")

    kernel = contents["qemu/Image"]
    kernel_end = KERNEL_OFFSET + len(kernel)
    for name in ("cartesi/linux.bin", "rvvm/linux.bin"):
        embedded = contents[name][KERNEL_OFFSET:kernel_end]
        assert embedded == kernel, f"{name}: embedded kernel differs from qemu/Image"
    print("All platform images contain the same Linux kernel.")

    stress_hash = sha256_file(STRESS_NG)
    assert stress_hash == STRESS_NG_HASH, f"guest/stress-ng-musl: expected {STRESS_NG_HASH}, got {stress_hash}"
    print(f"{stress_hash}  guest/stress-ng-musl")

    if ROOTFS.exists():
        rootfs_hash = sha256_file(ROOTFS)
        assert rootfs_hash == ROOTFS_HASH, f"rootfs-bench.ext2: expected {ROOTFS_HASH}, got {rootfs_hash}"
        print(f"{rootfs_hash}  rootfs-bench.ext2")
    elif require_rootfs:
        raise FileNotFoundError("run prepare-rootfs.sh before benchmarking")
    else:
        print("rootfs-bench.ext2 is absent; run prepare-rootfs.sh to create it.")


if __name__ == "__main__":
    verify_images()
