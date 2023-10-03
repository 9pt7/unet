use std::env;
use std::process::Command;

fn main() {
    // Get the cargo directory
    let cargo_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Run docker build
    let status = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg("unet")
        .arg(cargo_dir)
        .status()
        .unwrap();

    if !status.success() {
        panic!("docker build failed");
    }
}
