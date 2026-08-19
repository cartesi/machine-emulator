#!/usr/bin/env python3
"""Verify the committed cross-emulator Linux boot artifacts."""

import hashlib
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGES = HERE / "images"
KERNEL_OFFSET = 2 * 1024 * 1024

EXPECTED = {
    "cartesi/linux.bin": (17545256, "551ed4dae2b82ed59b4055f18d525a77f5ee35605acbf1238ff83e0cf9bfc3f1"),
    "qemu/Image": (15448096, "c570a15a4cd484088e72f8f28bf74e404888904ed00768433a68b33f10c8c4c0"),
    "rvvm/linux.bin": (17545248, "c2370b05b683d511851279c5c3f637873a334898597db283c11a2da413bffa13"),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_images():
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


if __name__ == "__main__":
    verify_images()
