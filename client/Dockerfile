FROM rust:1.79 as builder

WORKDIR /usr/src/zkp_auth
COPY . .

# Install dependencies and cross-compilation toolchain
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    musl-tools \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Set up cross-compilation environment
ENV CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
ENV AR_aarch64_unknown_linux_musl=aarch64-linux-gnu-ar

RUN rustup target add aarch64-unknown-linux-musl
RUN cargo build --release --package client --target aarch64-unknown-linux-musl

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/zkp_auth/target/aarch64-unknown-linux-musl/release/client /usr/local/bin/client