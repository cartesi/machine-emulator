FROM diegonehab/themis:sys

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

# Delete unnecessary stuff
# ----------------------------------------------------
RUN \
    cd $BASE && \
    \rm -rf freedom-u-sdk && \
    \rm -rf rv64ima-lp64

COPY run-qemu.sh $BASE

USER root

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
