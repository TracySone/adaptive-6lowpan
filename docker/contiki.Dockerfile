ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}
ARG DEBIAN_FRONTEND=noninteractive
ARG CONTIKI_REF=release/v4.8
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates gcc-arm-none-eabi git make \
    openjdk-17-jdk-headless python3 \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${CONTIKI_REF}" \
    https://github.com/contiki-ng/contiki-ng.git /opt/contiki-ng
WORKDIR /workspace
COPY . .
CMD ["bash", "-lc", \
     "make -C platform/contiki-ng CONTIKI=/opt/contiki-ng TARGET=native"]
