ARG UBUNTU_VERSION=24.04

FROM ubuntu:${UBUNTU_VERSION} AS liboqs-builder
ARG DEBIAN_FRONTEND=noninteractive
ARG LIBOQS_VERSION=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake git ninja-build libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git /src/liboqs
RUN cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_512" \
    -DBUILD_SHARED_LIBS=OFF \
    && cmake --build /src/liboqs/build \
    && cmake --install /src/liboqs/build

FROM ubuntu:${UBUNTU_VERSION}
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs-builder /opt/liboqs /opt/liboqs
ENV PKG_CONFIG_PATH=/opt/liboqs/lib/pkgconfig:/opt/liboqs/lib64/pkgconfig
WORKDIR /workspace
COPY . .
RUN make test
RUN make production
CMD ["bash", "-lc", "make test && ./build/adaptive_demo --steps 24"]
