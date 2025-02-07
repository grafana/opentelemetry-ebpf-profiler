FROM debian:bookworm as rust-builder
RUN apt-get update && apt-get -y install wget gcc curl cmake protobuf-compiler

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY Cargo.lock Cargo.toml /profiler/
COPY rust-crates /profiler/rust-crates

WORKDIR /profiler
RUN cargo build --release



FROM golang:1.23-bookworm as builder

WORKDIR /profiler

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


COPY --from=rust-builder /profiler/target/release/libsymblib_capi.a /profiler/target/release/libsymblib_capi.a
RUN /usr/local/go/bin/go build  .

FROM debian:bookworm

#RUN apt-get update && \
#    apt-get install -y linux-headers-generic && \
#    rm -rf /var/lib/apt/lists/*

COPY --from=builder /profiler/ebpf-profiler /usr/local/bin/


