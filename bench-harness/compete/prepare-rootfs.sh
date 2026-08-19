#!/bin/sh
# Build the byte-reproducible rootfs used by the cross-emulator benchmarks.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output=${1:-"$script_dir/rootfs-bench.ext2"}
base_rootfs="$repo_dir/tests/build/images/rootfs.ext2"
stress_ng="$script_dir/guest/stress-ng-musl"

base_hash=a240082c3b5988f40e6ab0677bf362a057a13431ac6f2c409568bcc87510b243
stress_hash=26caa5259058a82388e537d18d6ac8afee8e0bbb56ddcfd2a13e79e05e508608
bench_init_hash=694eaef1b15466e29328405c75fb72f6408d75c1df6e58e8c85e15c7135a40be
output_hash=3f6ad0dba2a74d62792794b411dd0791fae194fdf639512b7c9feddb1829eee9

for required_tool in make shasum e2cp debugfs dd; do
    command -v "$required_tool" >/dev/null || {
        echo "prepare-rootfs: missing required tool: $required_tool" >&2
        exit 1
    }
done

make -C "$repo_dir/tests" images
printf '%s  %s\n' "$base_hash" "$base_rootfs" | shasum -a 256 -c -
printf '%s  %s\n' "$stress_hash" "$stress_ng" | shasum -a 256 -c -
printf '%s  %s\n' "$bench_init_hash" "$script_dir/bench-init" | shasum -a 256 -c -

task_tmp=$(mktemp "${output}.tmp.XXXXXX")
trap 'rm -f "$task_tmp"' EXIT HUP INT TERM
cp "$base_rootfs" "$task_tmp"

# Set a temporary host-independent owner before restoring the metadata from
# the measured image below.
e2cp -P 755 -O 0 -G 0 "$stress_ng" "$task_tmp:/usr/bin/stress-ng-musl"
e2cp -P 755 -O 0 -G 0 "$script_dir/bench-init" "$task_tmp:/usr/sbin/bench-init"

# Restore the exact inode metadata of the filesystem used for the recorded
# measurements. This makes the result byte-identical instead of merely
# content-equivalent. e2cp otherwise records the caller's UID, GID and time.
for guest_file in /usr/bin/stress-ng-musl /usr/sbin/bench-init; do
    debugfs -w -R "set_inode_field $guest_file uid 501" "$task_tmp" >/dev/null 2>&1
    debugfs -w -R "set_inode_field $guest_file gid 20" "$task_tmp" >/dev/null 2>&1
done
for inode_field in atime ctime mtime; do
    debugfs -w -R "set_inode_field /usr/bin/stress-ng-musl $inode_field 0x6a8454b3" "$task_tmp" \
        >/dev/null 2>&1
    debugfs -w -R "set_inode_field /usr/sbin/bench-init $inode_field 0x6a8454a6" "$task_tmp" \
        >/dev/null 2>&1
done

# s_wtime is the 32-bit field 48 bytes into the primary ext2 superblock,
# which begins at byte 1024. Store 0x6a8454b3 in little-endian order.
printf '\263\124\204\152' | dd of="$task_tmp" bs=1 seek=1072 conv=notrunc 2>/dev/null

printf '%s  %s\n' "$output_hash" "$task_tmp" | shasum -a 256 -c -
mv "$task_tmp" "$output"
trap - EXIT HUP INT TERM
echo "Created $output"
