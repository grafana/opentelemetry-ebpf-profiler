FROM ubuntu:22.04 as builder
RUN apt-get update && apt-get -y install wget gcc curl cmake protobuf-compiler
RUN wget https://go.dev/dl/go1.22.10.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.22.10.linux-amd64.tar.gz

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /profiler
WORKDIR /profiler
RUN cargo build --release
RUN /usr/local/go/bin/go build -ldflags="-s -w"  .

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y linux-headers-generic && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /profiler/ebpf-profiler /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/ebpf-profiler"]