FROM ubuntu:20.04 as builder

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential wget git \
        libreadline-dev libboost-container-dev libboost-program-options-dev \
        libboost-serialization-dev protobuf-compiler protobuf-compiler-grpc \
        libprotobuf-dev libgrpc++-dev \
        ca-certificates automake libtool patchelf && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/emulator
COPY . .

RUN make -j$(nproc) dep && \
    make -j$(nproc) && \
    make install && \
    make clean && \
    rm -rf *

FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    libboost-program-options1.71.0 \
    libboost-serialization1.71.0 \
    libprotobuf17 \
    libprotobuf-lite17 \
    libgrpc++1 \
    libreadline8 \
    openssl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/cartesi/bin:${PATH}"
WORKDIR /opt/cartesi
COPY --from=builder /opt/cartesi .

CMD [ "/opt/cartesi/bin/cartesi-machine-server" ]
