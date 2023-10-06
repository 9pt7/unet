FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl \
    unzip

# Install AWS SAM CLI
RUN curl -L https://github.com/aws/aws-sam-cli/releases/download/v1.97.0/aws-sam-cli-linux-x86_64.zip -o /tmp/aws-sam-cli.zip && \
    unzip /tmp/aws-sam-cli.zip -d /tmp/aws-sam-cli && \
    /tmp/aws-sam-cli/install && \
    rm -rf /tmp/aws-sam-cli-linux-x86_64 /tmp/aws-sam-cli.zip

# Install build dependencies
RUN apt-get install -y build-essential

# Create a new user account named 'user' with a home directory
RUN useradd --create-home user
RUN chown -R user:user /home/user

# Switch to the user acount
USER user

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Update the PATH environment variable to include cargo
ENV PATH="/home/user/.cargo/bin:${PATH}"
ENV RUSTUP_HOME="/home/user/.rustup"
ENV CARGO_HOME="/home/user/.cargo"

# Set the default toolchain
RUN rustup default 1.72.0


USER root
RUN apt install -y git
USER root


# Copy the source code into the container
COPY --chown=user:user . /home/user/unet

# Set the working directory to the project root
WORKDIR /home/user/unet

ENV RUST_BACKTRACE=full

# Build the project with a build cache
RUN --mount=type=cache,target=/home/user/unet/target \
    cargo build --tests --release --bins

# RUN cargo build --tests --release --bins

# Install the binaries
RUN cargo install --path /home/user/unet --bins
