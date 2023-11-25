unet
====

[unet](https://unet.tech) lets you run a network application on a single virtual machine by making many machines appear as a single machine. It scales to millions of simultaneous hosts. unet supports storage and transmission of data through files. The files are hosted on a distributed filesystem so data can be shared. Nearly any computer with a public internet connection can connect to unet, allowing unet to support a range of [use cases](/src/use-cases.md). Using unet, you can write scalable network applications fully in Rust that runs across all [supported platforms](src/platforms).

- [Features](#features)
- [Development](#development)

# Features
- [Security](#security)


## Security

Users control how their data is shared. It is free for anyone to sign up to unet, so it is important that permissions are properly managed.

# Development

This repository contains the client code. It is written in [Rust](https://www.rust-lang.org/), but has bindings for C/C++, Javascript/Typescript, and Python.

- [Contributing](#contributing)

## Contributing

# License

MIT
