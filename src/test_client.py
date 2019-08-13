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
sys.path.insert(0,'../lib/grpc-interfaces/py/')

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
DIR_PATH = os.path.dirname(os.path.realpath(__file__))

TEST_ROM = {
    BOOTARGS: "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw {} -- /bin/echo nice && ls /mnt",
    BACKING: "rom-linux.bin"
}

TEST_RAM = {
    LENGTH: 64 << 20, #2**26 or 67108864
    BACKING: "kernel.bin"

}

BACKING_TEST_DRIVE_FILEPATH = "rootfs.ext2"

TEST_DRIVES = [
    {
        START: 1 << 63, #2**63 or ~ 9*10**18
        LENGTH: os.path.getsize(BACKING_TEST_DRIVE_FILEPATH),
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
    ram_msg = cartesi_base_pb2.RAM(length=TEST_RAM[LENGTH], backing=DIR_PATH + '/' + TEST_RAM[BACKING])
    drives_msg = []
    for drive in TEST_DRIVES:
        drive_msg = cartesi_base_pb2.Drive(start=drive[START], length=drive[LENGTH], backing=DIR_PATH + '/' + drive[BACKING],
                                           shared=drive[SHARED], label=drive[LABEL])
        drives_msg.append(drive_msg)
    bootargs_str = TEST_ROM[BOOTARGS].format(build_mtdparts_str(TEST_DRIVES))
    rom_msg = cartesi_base_pb2.ROM(bootargs=bootargs_str, backing=DIR_PATH + '/' + TEST_ROM[BACKING])
    processor_state_msg = cartesi_base_pb2.ProcessorState(x1=5)
    processor_msg = cartesi_base_pb2.Processor(state=processor_state_msg)
    return cartesi_base_pb2.MachineRequest(processor=processor_msg, rom=rom_msg, ram=ram_msg, flash=drives_msg)

def get_args():
    parser = argparse.ArgumentParser(description='GRPC client to the low level emulator API')
    parser.add_argument('server_add', help="Emulator GRPC server address")
    args = parser.parse_args()

    srv_add = "localhost:50000"

    if args.server_add:
        srv_add = args.server_add

    return srv_add

def run():
    response, response2, response3, response4 = (None, None, None, None)
    srv_add = get_args()

    print("Connecting to server in " + srv_add)
    with grpc.insecure_channel(srv_add) as channel:
        stub = core_pb2_grpc.MachineStub(channel)
        try:
            response = stub.Machine(make_new_machine_request())
            response2 = stub.GetRootHash(cartesi_base_pb2.Void())
            run_msg = cartesi_base_pb2.RunRequest(limit=500000000)
            response3 = stub.Run(run_msg)
            response4 = stub.Step(cartesi_base_pb2.Void())
            #DEBUG
            #embed()
            response5 = stub.Shutdown(cartesi_base_pb2.Void())
        except Exception as e:
            print("An exception occurred:")
            print(e)
            print(type(e))
    if (response):
        print("Core client received: " + str(response))
    if (response2):
        print("Core client received2: " + str(response2))
    if (response3):
        print("Core client received3: " + str(response3))
    if (response4):
        print("Core client received4: " + str(response4))
    if (response5):
        print("Core client received5: " + str(response5))

if __name__ == '__main__':
    run()
