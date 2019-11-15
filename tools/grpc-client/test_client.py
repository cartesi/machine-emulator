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

import grpc
import sys
import os

#So the cartesi GRPC modules are in path
sys.path.insert(0,'./proto/')

import core_pb2
import cartesi_base_pb2
import core_pb2_grpc
import manager_low_pb2
import manager_low_pb2_grpc
import traceback
import argparse
#from IPython import embed

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
    LENGTH: 64 << 20, #2**26 or 67108864
    BACKING: "kernel.bin"

}

BACKING_TEST_DRIVE_FILEPATH = "rootfs.ext2"

TEST_DRIVES = [
    {
        START: 1 << 63, #2**63 or ~ 9*10**18
        LENGTH: os.path.getsize(os.path.join(DIR_PATH, BACKING_TEST_DRIVE_FILEPATH)),
        BACKING: BACKING_TEST_DRIVE_FILEPATH,
        SHARED: False,
        LABEL: "root filesystem"
    }
]

def build_mtdparts_str(drives):
    mtdparts_str = "mtdparts="
    for i,drive in enumerate(drives):
        mtdparts_str += "flash.%d:-(%s)".format(i, drive[LABEL])
    return mtdparts_str

def make_new_machine_request():
    ram_msg = cartesi_base_pb2.RAM(length=TEST_RAM[LENGTH], backing=os.path.join(DIR_PATH, TEST_RAM[BACKING]))
    drives_msg = []
    for drive in TEST_DRIVES:
        drive_msg = cartesi_base_pb2.Drive(start=drive[START], length=drive[LENGTH], backing=os.path.join(DIR_PATH, drive[BACKING]),
                                           shared=drive[SHARED], label=drive[LABEL])
        drives_msg.append(drive_msg)
    bootargs_str = TEST_ROM[BOOTARGS].format(build_mtdparts_str(TEST_DRIVES))
    rom_msg = cartesi_base_pb2.ROM(bootargs=bootargs_str, backing=os.path.join(DIR_PATH, TEST_ROM[BACKING]))
    processor_state_msg = cartesi_base_pb2.ProcessorState(x1=5)
    processor_msg = cartesi_base_pb2.Processor(state=processor_state_msg)
    return cartesi_base_pb2.MachineRequest(processor=processor_msg, rom=rom_msg, ram=ram_msg, flash=drives_msg)

def request(stub, func, *args):
    print("Executing {} request..".format(func) )
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
        stub = core_pb2_grpc.MachineStub(channel)
        content = bytes("Hello World!", "iso8859-1")
        mem_address = TEST_DRIVES[0][START]
        try:
            request(stub, "Machine", make_new_machine_request())
            request(stub, "GetRootHash", cartesi_base_pb2.Void())
            request(stub, "Run", cartesi_base_pb2.RunRequest(limit=500000000))
            request(stub, "Step", cartesi_base_pb2.Void())
            request(stub, "ReadMemory", cartesi_base_pb2.ReadMemoryRequest(address=mem_address, length=len(content)))
            request(stub, "WriteMemory", cartesi_base_pb2.WriteMemoryRequest(address=mem_address, data=content))
            request(stub, "GetProof", cartesi_base_pb2.GetProofRequest(address=mem_address, log2_size=3))
            request(stub, "Shutdown", cartesi_base_pb2.Void())
        except Exception as e:
            print("An exception occurred:")
            print(e)
            print(type(e))

if __name__ == '__main__':
    run()
