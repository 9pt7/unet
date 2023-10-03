use std::env;
use std::process::Command;

pub fn deploy() {
    // Get the cargo directory
    let cargo_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Run docker build
    let docker_build_ok = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg("unet")
        .arg(cargo_dir)
        .status()
        .unwrap()
        .success();

    if !docker_build_ok {
        panic!("docker build failed");
    }
}
