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
COPY . .

CMD [ "/opt/cartesi/bin/cartesi-machine-server" ]
