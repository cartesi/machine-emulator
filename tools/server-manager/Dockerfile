ARG EMULATOR_REPOSITORY=cartesi/machine-emulator
ARG EMULATOR_VERSION=latest

FROM ${EMULATOR_REPOSITORY}:${EMULATOR_VERSION} as grpc_health_probe
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y golang-go && \
    go install github.com/grpc-ecosystem/grpc-health-probe@2ff33ce40f97594e25068ca634d657b6aac4f72a

FROM ${EMULATOR_REPOSITORY}:${EMULATOR_VERSION}

LABEL maintainer="Victor Fusco <victor@cartesi.io>"

COPY --from=grpc_health_probe /root/go/bin/grpc-health-probe /usr/local/bin

WORKDIR /opt/cartesi/bin

CMD ["/opt/cartesi/bin/server-manager", "--manager-address=0.0.0.0:5001"]
