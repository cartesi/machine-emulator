# Copyright 2019 Cartesi Pte. Ltd.
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
#

from __future__ import print_function

import os
import sys
import argparse
import grpc

# So the cartesi GRPC modules are in path
sys.path.insert(0, './proto/')

import cartesi_machine_pb2
import cartesi_machine_pb2_grpc
# from IPython import embed

START = "start"
BACKING = "backing"
LENGTH = "length"
SHARED = "shared"
LABEL = "label"
BOOTARGS = "bootargs"
DIR_PATH = os.path.dirname(os.path.realpath("../../src/cartesi-machine-server"))

TEST_ROM = {
    BOOTARGS: "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw {} -- /bin/echo nice && ls /mnt",
    BACKING: "rom.bin"
    }

TEST_RAM = {
    LENGTH: 64 << 20,  # 2**26 or 67108864
    BACKING: "linux.bin"
    }

BACKING_TEST_DRIVE_FILEPATH = "rootfs.ext2"

TEST_DRIVES = [
    {
        START: 1 << 63,  # 2**63 or ~ 9*10**18
        LENGTH: os.path.getsize(os.path.join(DIR_PATH, BACKING_TEST_DRIVE_FILEPATH)),
        BACKING: BACKING_TEST_DRIVE_FILEPATH,
        SHARED: False,
        LABEL: "root filesystem"
        }
    ]


def build_mtdparts_str(drives):
    mtdparts_str = "mtdparts="
    for i, drive in enumerate(drives):
        mtdparts_str += "flash.%d:-(%s)".format(i, drive[LABEL])
    return mtdparts_str


def make_new_machine_request():
    ram_msg = cartesi_machine_pb2.RAMConfig(length=TEST_RAM[LENGTH], image_filename=os.path.join(DIR_PATH, TEST_RAM[BACKING]))
    drives_msg = []
    for drive in TEST_DRIVES:
        drive_msg = cartesi_machine_pb2.FlashDriveConfig(start=drive[START], length=drive[LENGTH], image_filename=os.path.join(DIR_PATH, drive[BACKING]),
                                                 shared=drive[SHARED])
        drives_msg.append(drive_msg)
    bootargs_str = TEST_ROM[BOOTARGS].format(build_mtdparts_str(TEST_DRIVES))
    rom_msg = cartesi_machine_pb2.ROMConfig(bootargs=bootargs_str, image_filename=os.path.join(DIR_PATH, TEST_ROM[BACKING]))
    processor_config = cartesi_machine_pb2.ProcessorConfig(x1=5)
    machine_config = cartesi_machine_pb2.MachineConfig(processor=processor_config, rom=rom_msg, ram=ram_msg, flash_drive=drives_msg)
    return cartesi_machine_pb2.MachineRequest(config=machine_config)


def request(stub, func, *args):
    print("Executing {} request..".format(func))
    response = getattr(stub, func)(*args)
    if not response:
        raise Exception("Unexpected {} response: {}".format(func, str(response)))
    print(func + " response: " + str(response))
    return response


def get_server_address():
    parser = argparse.ArgumentParser(description='GRPC client to the low level emulator API')
    parser.add_argument('server', nargs='?', default="127.0.0.1:50000",
                        help="Emulator GRPC server address (Default: 127.0.0.1:50000)")
    args = parser.parse_args()
    return args.server


def run():
    server_address = get_server_address()
    print("Connecting to cartesi-machine-server at " + server_address)
    with grpc.insecure_channel(server_address) as channel:
        stub = cartesi_machine_pb2_grpc.MachineStub(channel)
        content = bytes("Hello World!", "iso8859-1")
        mem_address = TEST_DRIVES[0][START]
        try:
            request(stub, "Machine", make_new_machine_request())
            request(stub, "GetRootHash", cartesi_machine_pb2.Void())
            request(stub, "Run", cartesi_machine_pb2.RunRequest(limit=500000000))
            request(stub, "Step", cartesi_machine_pb2.Void())
            request(stub, "ReadMemory", cartesi_machine_pb2.ReadMemoryRequest(address=mem_address, length=len(content)))
            request(stub, "WriteMemory", cartesi_machine_pb2.WriteMemoryRequest(address=mem_address, data=content))
            request(stub, "GetProof", cartesi_machine_pb2.GetProofRequest(address=mem_address, log2_size=3))
            request(stub, "Shutdown", cartesi_machine_pb2.Void())
        except Exception as e:
            print("An exception occurred:")
            print(e)
            print(type(e))


if __name__ == '__main__':
    run()
