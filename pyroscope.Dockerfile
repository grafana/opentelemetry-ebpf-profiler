FROM --platform=$BUILDPLATFORM ubuntu:noble as rust-builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM


RUN mkdir -p /etc/apt/sources.list.d && \
    echo 'Types: deb\n\
URIs: http://azure.archive.ubuntu.com/ubuntu/\n\
Suites: noble noble-updates noble-backports\n\
Components: main universe restricted multiverse\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
Architectures: amd64\n\
\n\
Types: deb\n\
URIs: http://azure.ports.ubuntu.com/ubuntu-ports/\n\
Suites: noble noble-updates noble-backports\n\
Components: main universe restricted multiverse\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
Architectures: arm64' > /etc/apt/sources.list.d/ubuntu.sources && \
    dpkg --add-architecture arm64 && \
    apt-get update

RUN apt-get install -y curl unzip gcc-aarch64-linux-gnu \
  libc6-arm64-cross qemu-user-binfmt libc6:arm64 \
  musl-dev:amd64 musl-dev:arm64 musl-tools binutils-aarch64-linux-gnu gcc cmake wget

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.77
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add aarch64-unknown-linux-musl
RUN rustup target add x86_64-unknown-linux-musl

RUN wget -q "https://github.com/protocolbuffers/protobuf/releases/download/v24.4/protoc-24.4-linux-x86_64.zip" \
       && unzip "protoc-24.4-linux-x86_64.zip" -d "/usr/local" 'bin/*' 'include/*' \
        && chmod +xr "/usr/local/bin/protoc" \
        && find "/usr/local/include" -type d -exec chmod +x {} \; \
        && find "/usr/local/include" -type f -exec chmod +r {} \; \
        && rm "protoc-24.4-linux-x86_64.zip"

COPY .cargo /profiler/.cargo
COPY Cargo.lock Cargo.toml /profiler/
COPY rust-crates /profiler/rust-crates

WORKDIR /profiler
RUN cargo fetch

RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    cargo build --lib --release --target aarch64-unknown-linux-musl; \
else \
    cargo build --lib --release --target x86_64-unknown-linux-musl; \
fi ;


FROM --platform=$BUILDPLATFORM golang:1.23-bookworm as builder
ARG BUILDPLATFORM
ARG TARGETARCH
WORKDIR /profiler

RUN apt-get update && apt-get install -y gcc gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu

COPY go.mod go.sum  /profiler/
RUN go mod download
COPY main.go cli_flags.go /profiler/

COPY armhelpers /profiler/armhelpers
COPY collector /profiler/collector
COPY host /profiler/host
COPY internal /profiler/internal
COPY interpreter /profiler/interpreter
COPY libpf /profiler/libpf
COPY lpm /profiler/lpm
COPY maccess /profiler/maccess
COPY metrics /profiler/metrics
COPY nativeunwind /profiler/nativeunwind
COPY nopanicslicereader /profiler/nopanicslicereader
COPY pacmask /profiler/pacmask
COPY periodiccaller /profiler/periodiccaller
COPY proc /profiler/proc
COPY process /profiler/process
COPY processmanager /profiler/processmanager
COPY remotememory /profiler/remotememory
COPY reporter /profiler/reporter
COPY rlimit /profiler/rlimit
COPY stringutil /profiler/stringutil
COPY successfailurecounter /profiler/successfailurecounter
COPY support /profiler/support
COPY testsupport /profiler/testsupport
COPY times /profiler/times
COPY tools /profiler/tools
COPY tpbase /profiler/tpbase
COPY tracehandler /profiler/tracehandler
COPY tracer /profiler/tracer
COPY traceutil /profiler/traceutil
COPY util /profiler/util
COPY vc /profiler/vc
COPY zydis /profiler/zydis
COPY pyroscope /profiler/pyroscope

COPY --from=rust-builder /profiler/target/ /profiler/target/

ENV CGO_ENABLED=1
ENV GOARCH=$TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
    export ARCH_PREFIX=aarch64-linux-gnu-; \
    export CC=${ARCH_PREFIX}gcc; \
    export OBJCOPY=${ARCH_PREFIX}objcopy; \
    /usr/local/go/bin/go build -buildvcs=false \
      -ldflags="-extldflags=-static -extldflags=target/aarch64-unknown-linux-musl/release/libsymblib_capi.a" \
      -tags osusergo,netgo ; \
else \
    export ARCH_PREFIX=x86_64-linux-gnu-; \
    export CC=${ARCH_PREFIX}gcc; \
    export OBJCOPY=${ARCH_PREFIX}objcopy ; \
    /usr/local/go/bin/go build -buildvcs=false \
          -ldflags="-extldflags=-static -extldflags=target/x86_64-unknown-linux-musl/release/libsymblib_capi.a" \
          -tags osusergo,netgo ; \
fi


FROM debian:bookworm

COPY --from=builder /profiler/ebpf-profiler /usr/local/bin/


