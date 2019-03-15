#!/bin/bash

GRPC_DIR=../../cartesi-grpc
GRPC_PY_DIR=$GRPC_DIR/py
python -m grpc_tools.protoc -I$GRPC_DIR --python_out=$GRPC_PY_DIR --grpc_python_out=$GRPC_PY_DIR $GRPC_DIR/core.proto
python -m grpc_tools.protoc -I$GRPC_DIR --python_out=$GRPC_PY_DIR $GRPC_DIR/cartesi-base.proto
python -m grpc_tools.protoc -I$GRPC_DIR --python_out=$GRPC_PY_DIR --grpc_python_out=$GRPC_PY_DIR $GRPC_DIR/manager-low.proto


