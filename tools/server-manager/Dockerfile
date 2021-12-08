ARG EMULATOR_REPOSITORY=cartesi/machine-emulator
ARG EMULATOR_VERSION=latest
FROM ${EMULATOR_REPOSITORY}:${EMULATOR_VERSION}

LABEL maintainer="Victor Fusco <victor@cartesi.io>"

WORKDIR /opt/cartesi/bin

CMD ["/opt/cartesi/bin/server-manager", "--manager-address=0.0.0.0:5001"]
