FROM ubuntu:24.04

# Install dependencies
RUN apt update && apt install -y \
    clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev \
    pkg-config git iproute2 iputils-ping curl libssl-dev \
    linux-tools-common linux-tools-generic linux-headers-generic

# Build bpftool
RUN git clone https://github.com/libbpf/bpftool.git /tmp/bpftool && \
    cd /tmp/bpftool && git submodule update --init --recursive && \
    make -C src && \
    cp src/bpftool /usr/local/bin/ && \
    rm -rf /tmp/bpftool

# Set working dir
WORKDIR /app

# Copy project files
COPY . /app

# Build XDP userspace + kernel parts
RUN make clean && make

# Set BTF path agar libbpf bisa menemukan kernel BTF
ENV BPF_BTF_PATH=/sys/kernel/btf/vmlinux

# Default command
CMD ["bash"]

# Copy project source code
WORKDIR /app
COPY . /app

# Build your XDP app
RUN make clean && make
