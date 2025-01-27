# This Dockerfile is used to build a Docker image for the seedpass application using MUSL for ARM64

# docker buildx create --use
# docker buildx inspect --bootstrap
# docker buildx build --platform linux/arm64 -t seedpass-arm64-musl --load .
# docker run --rm --platform=linux/arm64 seedpass-arm64-musl /usr/local/bin/seedpass --help

# Stage 1: Build the Rust application with MUSL targeting ARM64
FROM messense/rust-musl-cross:aarch64-musl AS builder

# Set the target for ARM64 using MUSL
ENV TARGET=aarch64-unknown-linux-musl

# Add Rust target for cross-compilation
RUN rustup target add ${TARGET}

# Prepare the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Ensure Cargo is updated to the latest stable version
RUN rustup update && rustup default stable

# Compile the application with release optimizations
RUN cargo build --release --target ${TARGET}

# Stage 2: Create a lightweight final image with Alpine Linux
FROM alpine:latest

# Set security settings to prevent access to sensitive memory
RUN echo "kernel.yama.ptrace_scope=2" >> /etc/sysctl.conf \
    && echo "kernel.kptr_restrict=2" >> /etc/sysctl.conf

# Install runtime dependencies required for MUSL
RUN apk add --no-cache musl

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/seedpass /usr/local/bin/seedpass

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/seedpass

# Set the default command to show help
CMD ["/usr/local/bin/seedpass", "--help"]
