ARG TAG=devel
FROM cartesi/machine-emulator:builder AS tests-builder
ARG DEBUG=no
ARG COVERAGE=no
ARG SANITIZE=no

RUN make -j$(nproc) build-tests-machine debug=$DEBUG coverage=$COVERAGE sanitize=$SANITIZE
RUN make -j$(nproc) build-tests-misc build-tests-uarch build-tests-images debug=$DEBUG coverage=$COVERAGE sanitize=$SANITIZE

####################################################################################################
FROM tests-builder AS tests-debian-packager

RUN make tests-debian-package DESTDIR=$PWD/dpkg/tests-install && \
    make tests-data-debian-package DESTDIR=$PWD/dpkg/tests-data-install

####################################################################################################
FROM cartesi/machine-emulator:$TAG

ENV CARTESI_IMAGES_PATH=/usr/share/cartesi-machine/tests/data/images
ENV CARTESI_TESTS_PATH=/usr/share/cartesi-machine/tests/data/machine
ENV CARTESI_TESTS_UARCH_PATH=/usr/share/cartesi-machine/tests/data/uarch
ENV CARTESI_CMIO_PATH=/tmp/cartesi-machine/tests/data/cmio
ENV CARTESI_STEP_LOGS_PATH=/tmp/cartesi-machine/tests/data/step-logs

USER root

COPY --from=tests-debian-packager /usr/src/emulator/machine-emulator-tests*.deb .
RUN <<EOF
set -e
export DEBIAN_FRONTEND="noninteractive"
apt-get update
apt-get install -y ./machine-emulator-tests*.deb
rm -rf /var/lib/apt/lists/* machine-emulator-tests*.deb
mkdir -p ${CARTESI_CMIO_PATH}
chown -R cartesi:cartesi ${CARTESI_CMIO_PATH}
EOF

USER cartesi
