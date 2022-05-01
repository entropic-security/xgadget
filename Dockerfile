FROM ubuntu:20.04

# Kernel build pre-reqs
# See: https://www.linux.com/topic/desktop/how-compile-linux-kernel-0/
ENV TZ=US/New_York
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y \
    apt-utils \
    tzdata \
    sudo \
    curl \
    git \
    fakeroot \
    build-essential \
    ncurses-dev \
    xz-utils \
    libssl-dev \
    bc \
    flex \
    libelf-dev \
    bison

# Rust toolchain
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y
ENV PATH=/root/.cargo/bin:$PATH

# Src import
RUN mkdir /xgadget
WORKDIR /xgadget
COPY . /xgadget

# Test and install
RUN cargo test --all-features
RUN cargo install --path . --features cli-bin

# Build kernels for benchmarking
RUN ./benches/bench_setup_ubuntu.sh
