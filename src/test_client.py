from __future__ import print_function

import grpc
import sys
import os

#So the cartesi GRPC modules are in path
sys.path.insert(0,'../../cartesi-grpc/py')

import core_pb2
import cartesi_base_pb2
import core_pb2_grpc
import manager_low_pb2
import manager_low_pb2_grpc
import traceback
import argparse
from IPython import embed

START = "start" 
BACKING = "backing"
LENGTH = "length"
SHARED = "shared"
LABEL = "label"
BOOTARGS = "bootargs"

TEST_ROM = {
    BOOTARGS: "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw -- /bin/echo nice"
}

TEST_RAM = {
    LENGTH: 64 << 20, #2**26 or 67108864
    BACKING: "/home/carlo/crashlabs/core/src/emulator/kernel.bin"
    
}

BACKING_TEST_DRIVE_FILEPATH = "/home/carlo/crashlabs/core/src/emulator/rootfs.ext2"

TEST_DRIVES = [
    {
        START: 1 << 63, #2**63 or ~ 9*10**18
        LENGTH: os.path.getsize(BACKING_TEST_DRIVE_FILEPATH),
        BACKING: BACKING_TEST_DRIVE_FILEPATH,
        SHARED: False,
        LABEL: "root filesystem"
    }
]

def make_new_machine_request():
    rom_msg = cartesi_base_pb2.ROM(bootargs=TEST_ROM[BOOTARGS])
    ram_msg = cartesi_base_pb2.RAM(length=TEST_RAM[LENGTH], backing=TEST_RAM[BACKING])
    drives_msg = []
    for drive in TEST_DRIVES:
        drive_msg = cartesi_base_pb2.Drive(start=drive[START], length=drive[LENGTH], backing=drive[BACKING], 
                                           shared=drive[SHARED], label=drive[LABEL])
        drives_msg.append(drive_msg)
    processor_state_msg = cartesi_base_pb2.ProcessorState(x1=5)
    processor_msg = cartesi_base_pb2.Processor(state=processor_state_msg)
    return cartesi_base_pb2.MachineRequest(processor=processor_msg, rom=rom_msg, ram=ram_msg, flash=drives_msg)

def address(add):
    #TODO: validate address
    return add

def port_number(port):
    try:
        int_port = int(port)
        if not(0 <= int_port <= 65535):
            raise argparse.ArgumentTypeError("Please provide a valid port from 0 to 65535")
    except:
        raise argparse.ArgumentTypeError("Please provide a valid port from 0 to 65535")
    return port
   
def get_args():
    parser = argparse.ArgumentParser(description='GRPC client to the low level emulator API')
    parser.add_argument('server_add', type=address, help="Emulator GRPC server address")
    parser.add_argument('server_port', type=port_number, help="Emulator GRPC server port")
    args = parser.parse_args()

    srv_add = "localhost"
    srv_port = "50000"
    
    if args.server_add:
        srv_add = args.server_add

    if args.server_port:
        srv_port = args.server_port

    return (srv_add, srv_port) 

def run():
    response, response2, response3, response4 = (None, None, None, None)
    srv_add, srv_port = get_args()
    conn_str = srv_add + ':' + srv_port
    print("Connecting to server in " + conn_str)
    with grpc.insecure_channel(conn_str) as channel:
        stub = core_pb2_grpc.MachineStub(channel)
        try:
            response = stub.Machine(make_new_machine_request())
            response2 = stub.GetRootHash(cartesi_base_pb2.Void())
            run_msg = cartesi_base_pb2.RunRequest(limit=500000000)
            response3 = stub.Run(run_msg)            
            response4 = stub.Step(cartesi_base_pb2.Void())
            embed()
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
