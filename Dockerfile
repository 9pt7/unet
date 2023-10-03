FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl \
    unzip

# Install AWS SAM CLI
RUN curl -L https://github.com/aws/aws-sam-cli/releases/download/v1.97.0/aws-sam-cli-linux-x86_64.zip -o /tmp/aws-sam-cli.zip && \
    unzip /tmp/aws-sam-cli.zip -d /tmp/aws-sam-cli && \
    /tmp/aws-sam-cli/install && \
    rm -rf /tmp/aws-sam-cli-linux-x86_64 /tmp/aws-sam-cli.zip

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Update the PATH environment variable to include cargo
ENV PATH="/root/.cargo/bin:${PATH}"
