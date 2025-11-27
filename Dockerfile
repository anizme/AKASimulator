# ----- Build on Ubuntu 20.04 (GLIBC 2.31) -----
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build tools + dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ninja-build pkg-config \
    libelf-dev libdw-dev libcapstone-dev libdwarf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working dir
WORKDIR /project

# Copy whole project into container
COPY . /project

# Create build directory
RUN mkdir -p build

# Build project with cmake + make
RUN cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j$(nproc)

# Build output: AKASimulator is placed at project root by your CMakeLists
