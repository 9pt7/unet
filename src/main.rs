use clap::Parser;
use unet::cloud::{
    get_api_domain, get_auth_domain, get_hosted_zone_id, get_root_domain, get_stack_name,
    get_websocket_domain, login, logout,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    subcommand: Option<Subcommand>,
}

fn set_env_vars() {
    let stack_id = "fdf39026-197e-4a0e-bdc3-a72b9b5b031e";
    let hosted_zone_id = "Z05848283TO5CBMZHZTRN";

    let common_domain = format!("{}.dev.unet.tech", stack_id);

    let root_domain = format!("https://{}", common_domain);
    let api_domain = format!("https://api.{}", common_domain);
    let websocket_domain = format!("wss://wss.api.{}", common_domain);
    let auth_domain = format!("https://auth.{}", common_domain);

    std::env::set_var("UNET_STACK_ID", stack_id);
    std::env::set_var("UNET_HOSTED_ZONE_ID", hosted_zone_id);
    std::env::set_var("UNET_ROOT_DOMAIN", root_domain.as_str());
    std::env::set_var("UNET_API_DOMAIN", api_domain.as_str());
    std::env::set_var("UNET_WEBSOCKET_DOMAIN", websocket_domain.as_str());
    std::env::set_var("UNET_AUTH_DOMAIN", auth_domain.as_str());
}

async fn set_current_dir_to_project_root() {
    let cargo = match std::env::var("CARGO") {
        Ok(msg) => msg,
        Err(_) => "cargo".to_string(),
    };

    let output = tokio::process::Command::new(cargo)
        .args(["metadata", "--format-version=1"])
        .output()
        .await
        .unwrap();
    let metadata: Metadata = serde_json::from_slice(&output.stdout).unwrap();

    // Set the working directory to the root of the project
    std::env::set_current_dir(metadata.workspace_root).unwrap();
}

async fn get() {
    println!("Hello, world!");
}

async fn exec(cli: &Cli) {
    set_env_vars();
    set_current_dir_to_project_root().await;
    match &cli.subcommand {
        None => get().await,
        Some(Subcommand::Build {}) => build().await,
        Some(Subcommand::Deploy(_deploy)) => deploy().await,
        Some(Subcommand::Test {}) => test().await,
        Some(Subcommand::Login {}) => login().await,
        Some(Subcommand::Logout {}) => logout().await,
    }
}

async fn build() {
    // Create the dist/s3 directory if it doesn't exist
    tokio::fs::create_dir_all("dist/s3").await.unwrap();

    // Build the lambda code
    run_build_command(&[
        "cargo",
        "lambda",
        "build",
        "--features",
        "aws",
        "--bin",
        "lambda",
        "--lambda-dir",
        "dist",
        "--release",
    ])
    .await;

    // Build the web assets
    run_build_command(&[
        "trunk",
        "build",
        "--features",
        "browser",
        "--dist",
        "dist/s3/www",
        "--release",
    ])
    .await;
}

async fn run_build_command(args: &[&str]) {
    let status = tokio::process::Command::new(args[0])
        .args(&args[1..])
        .status()
        .await
        .unwrap();
    if !status.success() {
        let full_command_str = args
            .iter()
            .map(|&s| s.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        panic!("Build command failed: {}", full_command_str);
    }
}

async fn test() {
    build().await;
    deploy().await;
}

async fn deploy() {
    build().await;

    let root_domain = get_root_domain();
    let api_domain = get_api_domain();
    let websocket_domain = get_websocket_domain();
    let auth_domain = get_auth_domain();

    let stack_name = get_stack_name();

    // Invoke `sam deploy`
    run_build_command(&[
        "sam",
        "deploy",
        "--no-fail-on-empty-changeset",
        "--region",
        "us-east-1",
        "--stack-name",
        stack_name.as_str(),
        "--capabilities",
        "CAPABILITY_IAM",
        "--no-confirm-changeset",
        "--no-disable-rollback",
        "--resolve-s3",
        "--parameter-overrides",
        format!("HostedZoneId={}", get_hosted_zone_id()).as_str(),
        format!("RootDomain={}", root_domain.host_str().unwrap()).as_str(),
        format!("ApiDomain={}", api_domain.host_str().unwrap()).as_str(),
        format!("WebSocketDomain={}", websocket_domain.host_str().unwrap()).as_str(),
        format!("AuthDomain={}", auth_domain.host_str().unwrap()).as_str(),
    ])
    .await;

    // Sync the browser dist dir to the S3 bucket and delete old files.
    run_build_command(&[
        "aws",
        "s3",
        "sync",
        "--delete",
        "dist/s3",
        format!("s3://{}/", get_stack_name()).as_str(),
    ])
    .await;
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Compile the current package for each platform
    Build {},
    /// Deploy the application.
    ///
    /// This will build the application and deploy it to AWS. It will also sync
    /// the browser assets to the S3 bucket.
    Deploy(Deploy),
    /// Run the tests
    Test {},
    /// Login to unet
    Login {},
    /// Logout of unet
    Logout {},
}

#[derive(Parser)]
struct Deploy {
    /// Delete the deployment
    #[clap(short, long)]
    delete: bool,
}

#[derive(serde::Deserialize)]
struct Metadata {
    workspace_root: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    exec(&cli).await;
}
