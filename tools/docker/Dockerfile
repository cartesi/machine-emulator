FROM ubuntu:20.04

MAINTAINER Diego Nehab <diego@cartesi.io>

ENV DEBIAN_FRONTEND=noninteractive

ENV BASE="/opt/emulator"

RUN \
    mkdir -p $BASE

RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential vim wget git libreadline-dev libboost-coroutine-dev \
        libboost-context-dev libboost-serialization-dev \
        protobuf-compiler protobuf-compiler-grpc libprotobuf-dev libgrpc++-dev \
        ca-certificates automake libtool patchelf && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="${PATH}:${BASE}/build/Linux_x86_64/bin"

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
