from __future__ import print_function

import grpc

import core_pb2
import core_pb2_grpc
import traceback
import argparse

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
    response = None
    srv_add, srv_port = get_args()
    conn_str = srv_add + ':' + srv_port
    print("Connecting to server in " + conn_str)
    with grpc.insecure_channel(conn_str) as channel:
        stub = core_pb2_grpc.MachineStub(channel)
        try:
            rom_msg = core_pb2.ROM(cmdline="-- /bin/echo nice")
            processor_msg = core_pb2.Processor(x1=5)
            response = stub.Machine(core_pb2.MachineRequest(rom=rom_msg, processor=processor_msg))
            run_msg = core_pb2.RunRequest(limit=50000000)
            response2 = stub.Run(run_msg)
            response3 = stub.Shutdown(core_pb2.Void())
        except Exception as e:
            print("An exception occurred:")
            print(e)
            print(type(e))
    if (response):
        print("Core client received: " + str(response2))


if __name__ == '__main__':
    run()
