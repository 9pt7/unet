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

# Switch to the user acount to install Rust
USER user

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Update the PATH environment variable to include cargo
ENV PATH="/home/user/.cargo/bin:${PATH}"
ENV RUSTUP_HOME="/home/user/.rustup"
ENV CARGO_HOME="/home/user/.cargo"

# Set the default toolchain
RUN rustup default 1.72.0

# Switch back to root for the rest of the installation
USER root
RUN apt install -y git

# Install Docker
# https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository

# Add Docker's official GPG key:
RUN apt update \
    && apt install ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources:
RUN echo \
    "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt update

ARG DOCKER_VERSION_STRING=5:24.0.6-1~ubuntu.22.04~jammy
RUN apt install -y \
    docker-ce=$DOCKER_VERSION_STRING \
    docker-ce-cli=$DOCKER_VERSION_STRING \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Install python3 + pip + cargo-lambda
RUN apt install -y python3 python3-pip \
    && pip3 install cargo-lambda

# Install trunk
RUN curl -L https://github.com/thedodd/trunk/releases/download/v0.17.5/trunk-x86_64-unknown-linux-gnu.tar.gz | tar -xzf- -C /usr/local/bin/ \
    && rustup target add wasm32-unknown-unknown

USER user

# Copy the source code into the container
COPY --chown=user:user . /home/user/unet

# Set the working directory to the project root
WORKDIR /home/user/unet

ENV RUST_BACKTRACE=full

# Build the project with a build cache
RUN --mount=type=cache,target=/home/user/unet/target \
    mkdir -p dist \
    && cargo lambda build --features="aws" --bin aws_lambda --lambda-dir dist \
    && trunk build --features "browser" --dist dist/browser
