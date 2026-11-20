# bip32-hydra: MP-SPDZ at commit e76014e (the copy of version 0.2.8 that the
# Hydra designers distribute with their reference code), built from the
# upstream repository, plus the tools the benchmarks use.
#
#   docker build -t bip32-hydra docker/
#
# Differences from the Hydra designers' copy of MP-SPDZ, which ran the
# measurements of the paper (see README.md, "MP-SPDZ version"): their copy adds
# CFLAGS += -DINSECURE to CONFIG, three "Warning generated ..." prints to
# Protocols/ReplicatedPrep.hpp, and an offline-party.x target. This image
# builds upstream unchanged, without -DINSECURE.

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        automake build-essential ca-certificates git libboost-dev \
        libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 \
        python3 python3-pip texinfo yasm \
        iproute2 time \
    && rm -rf /var/lib/apt/lists/*

# The compiler of this MP-SPDZ version imports Cryptodome for SHAKE128.
RUN pip3 install --no-cache-dir pycryptodomex

ARG MPSPDZ_COMMIT=e76014e2e9f9a0b8d6c3dc629c80ae3410ad1e70
# The submodule URL of mpir uses git://, which GitHub no longer serves.
RUN git config --global url."https://github.com/".insteadOf git://github.com/ \
 && git clone https://github.com/data61/MP-SPDZ.git /mp-spdz \
 && cd /mp-spdz && git checkout "$MPSPDZ_COMMIT"

WORKDIR /mp-spdz
RUN make -j"$(nproc)" tldr
RUN make -j"$(nproc)" shamir-party.x malicious-shamir-party.x mascot-party.x

CMD ["/bin/bash"]
