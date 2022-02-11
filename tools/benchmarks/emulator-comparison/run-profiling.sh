#!/bin/bash

# Copyright 2022 Cartesi Pte. Ltd.
#
# This file is part of the machine-emulator. The machine-emulator is free
# software: you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# The machine-emulator is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with the machine-emulator. If not, see http://www.gnu.org/licenses/.

cfg_name=output.cfg
rootfs_path=rootfs.ext2
kernel_bbl_path=kernel_bbl.bin
rom_path=rom.bin
cartesi_machine_path=/opt/cartesi/bin
flamegraph_path=/usr/bin

perf_data_name=perf.data
perf_folded_name=out.perf-folded

usage() {
    echo "Usage:
    $0 [options]
where options are:
    --help
        Prints this message.
    --kernel_bbl <path to kernel>
        Path to the ctsi kernel linked over the bbl bootloader.
        (default: $kernel_bbl_path)
    --rootfs <path to rootfs>
        Path to the rootfs.
        (default: $rootfs_path)
    --rom <path to rom>
        Path to rom.
        (default: $rom_path)
    --flamegraph <path to the FlameGraph utility>
        This script uses FlameGraph utility to build the output graphs.
        https://github.com/brendangregg/FlameGraph
        (default: $flamegraph_path)
    --cartesi_path <path to cartesi machine>
        Path to the directory containing cartesi-machine.lua script.
        (default: $cartesi_machine_path)"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --help)
      usage
      exit 0
      ;;
    --kernel_bbl)
      kernel_bbl_path="$2"
      shift
      shift
      ;;
    --rootfs)
      rootfs_path="$2"
      shift
      shift
      ;;
    --rom)
      rom_path="$2"
      shift
      shift
      ;;
    --cartesi_path)
      cartesi_machine_path="$2"
      shift
      shift
      ;;
    --flamegraph)
      flamegraph_path="$2"
      shift
      shift
      ;;
    -*|--*)
      echo "Unknown option $0"
      exit 1
      ;;
  esac
done

execute_cartesi_machine() {
    rootfs_length=$(wc -c $rootfs_path | awk '{print $1;}')
    cur_dir=$(pwd)
    cd $cartesi_machine_path
    perf record -g ./cartesi-machine.lua --ram-image=$kernel_bbl_path --rom-image=$rom_path --flash-drive=label:root,filename:$rootfs_path,start:0x8000000000000000,length:$rootfs_length -- "$1" &> /dev/null
    mv $perf_data_name $cur_dir/
    cd $cur_dir
}

do_profiling() {
    echo "----------"
    echo "Starting profiling '$1'"

    execute_cartesi_machine "$1"
    perf script | $flamegraph_path/stackcollapse-perf.pl > $perf_folded_name
    $flamegraph_path/flamegraph.pl $perf_folded_name > perf_$2.svg
    rm $perf_data_name $perf_folded_name
}


do_profiling "cd /benchmarks && java fasta 10" "fasta_java"
do_profiling "cd /benchmarks && java -Xint fasta 10" "fasta_java_nojit"
do_profiling "cd /benchmarks && ./fasta_c 10" "fasta_c"
do_profiling "cd /benchmarks && python3 fasta.py 10" "fasta_python"
do_profiling "cd /benchmarks && ./fasta_go 10" "fasta_go"
do_profiling "cd /benchmarks && ./fasta_rust 10" "fasta_rust"
