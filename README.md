unet is a distributed operating system in Rust. It provides a uniform cross-platform API for servers, the browser, mobile and IoT devices. Using unet, you can write distributed applications with a common code base in Rust that can run across all supported platforms.

# Development
[Sign up](https://unet.tech/signup) for unet (it's free), clone the [unet repository](https://github.com/9pt7/unet), then build and deploy (the dev stack is automatically deployed during `cargo build`):

```
git clone https://github.com/9pt7/unet.git
cd unet
cargo build
```

Copy the browser session host name after following [this link](https://unet.tech/redirect/user/dev/session), and shell into the session from your terminal:

```
peter@Peters-MacBook-Pro unet % cargo run
peter@dev.peter.unet.tech unet % whoami
peter
peter@dev.peter.unet.tech unet % hostname
dev.peter.unet.tech
peter@dev.peter.unet.tech unet % pwd
/home/peter/host/Peters-MacBook-Pro/dev/unet
peter@dev.peter.unet.tech unet % ls -la
total 24
drwxr-xr-x@  8 peter  peter   256  1 Oct 01:33 .
drwxr-x---+ 60 peter  peter  1920 30 Sep 21:53 ..
drwxr-xr-x@ 15 peter  peter   480  1 Oct 01:33 .git
drwxr-xr-x@  3 peter  peter    96 30 Sep 22:20 .github
-rw-r--r--@  1 peter  peter     8 30 Sep 21:55 .gitignore
-rw-r--r--@  1 peter  peter   173 30 Sep 21:55 Cargo.toml
-rw-r--r--@  1 peter  peter   267 30 Sep 22:20 README.md
drwxr-xr-x@  4 peter  peter   128 30 Sep 22:23 src
peter@dev.peter.unet.tech unet % cargo test
   Compiling unet v0.1.0 (/home/peter/dev/unet)
    Finished test [unoptimized + debuginfo] target(s) in 0.98s
     Running unittests src/main.rs (target/debug/deps/unet-6af04427f755a641)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

peter@dev.peter.unet.tech unet % cargo install --path .
  Installing unet v0.1.0 (/home/peter/dev/unet)
   Compiling unet v0.1.0 (/home/peter/dev/unet)
    Finished release [optimized] target(s) in 0.18s
  Installing /home/peter/.cargo/bin/unet
   Installed package `unet v0.1.0 (/home/peter/dev/unet)` (executable `unet`)

```

Running `cargo test` from the dev repository outside unet will automatically test across platforms.

# Installation
