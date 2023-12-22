ARG TAG=devel
FROM --platform=$TARGETPLATFORM cartesi/toolchain:0.16.0 as machine-tests-builder

COPY . /usr/src/emulator

WORKDIR /usr/src/emulator

RUN make -j$(nproc) build-tests-machine

FROM --platform=$TARGETPLATFORM cartesi/machine-emulator:builder as tests-builder

RUN make -j$(nproc) build-tests-misc build-tests-uarch build-tests-images

FROM tests-builder as tests-debian-packager
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

COPY --from=machine-tests-builder /usr/src/emulator/tests/build/machine /usr/src/emulator/tests/build/machine

RUN make tests-debian-package DESTDIR=$PWD/dpkg/tests-install && \
    make tests-data-debian-package DESTDIR=$PWD/dpkg/tests-data-install

FROM --platform=$TARGETPLATFORM cartesi/machine-emulator:$TAG
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

USER root

COPY --from=tests-debian-packager /usr/src/emulator/cartesi-machine-tests-*.deb .
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    ./cartesi-machine-tests-*.deb \
    && rm -rf /var/lib/apt/lists/* \
    && rm cartesi-machine-tests-*.deb

USER cartesi

ENV CARTESI_IMAGES_PATH=/usr/share/cartesi-machine/tests/data/images
ENV CARTESI_TESTS_PATH=/usr/share/cartesi-machine/tests/data/machine
ENV CARTESI_TESTS_UARCH_PATH=/usr/share/cartesi-machine/tests/data/uarch
