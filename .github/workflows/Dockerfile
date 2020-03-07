FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    libboost-program-options1.65.1 \
    libboost-serialization1.65.1 \
    libreadline7 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/cartesi/bin:${PATH}"
WORKDIR /opt/cartesi
COPY . .

CMD [ "/opt/cartesi/bin/cartesi-machine-server" ]
