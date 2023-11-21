use clap::Parser;
use unet::cloud::{
    get_api_domain, get_auth_domain, get_hosted_zone_id, get_root_domain, get_stack_name,
    get_websocket_domain, login, logout, register, serve, RegisterError, ServeError,
};

#[derive(Parser)]
#[command(author, version)]
/// unet is a distributed operating system.
///
/// This CLI provides the ability to interact with users and remote hosts
/// connected to unet, access unet's distributed filesystem, deploy code and
/// infrastructure, and more.
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Mount directories between unet's distributed filesystem and localhost.
    Mount {},
    /// Resolve a path on unet's distributed filesystem.
    Resolve {},
    /// Run a command on a host.
    ///
    /// Environment variables are not passed to the host except those that are
    /// explicitly specified. Moreover, some environment variables are
    /// automatically set and passed. For instance, `UNET_PWD` is set to `unet
    /// resolve .` and `UNET_ROOT` is set to `unet resolve /` so the host can
    /// resolve local file paths passed as arguments (see `unet resolve
    /// --help`).
    ///
    /// The host does not inherit permissions from the client. Also, the
    /// request is only issued if the host can read the current working
    /// directory.
    ///
    /// Each host hosts the `unet` CLI on unet to make it accessible to other
    /// priviledged hosts (so they can invoke `unet run <LOCALHOST>
    /// [COMMAND]...`). It follow that `unet run localhost [COMMAND]...` is
    /// equivalent to `unet [COMMAND]...`.
    ///
    /// To list the commands available to a host, run the `help` command on the
    /// host (`unet run <HOST> help`). To get help on a host's command or
    /// subcommand, use the `-h` or `--help` flag (`unet run <HOST>
    /// [COMMAND]... -h`).
    Run {
        /// The name of the host to run the command on
        host: String,
        /// The command to run and its arguments
        #[clap(allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Serve localhost on unet.
    ///
    /// localhost must be registered with unet before it can serve. See `unet
    /// register --help` for more information.
    Serve {
        /// List services that localhost serves
        #[clap(short, action = clap::ArgAction::SetTrue)]
        list: bool,
    },
    /// Create a unet shell.
    Shell {},
    /// Print the unet filesystem working directory.
    ///
    /// This is equivalent to `unet resolve .`.
    Pwd {},
    /// Manage authorization of users and hosts.
    ///
    /// Authorization rules are used to permit users and hosts to access files
    /// on a host. This is achieved by associating unet users and hosts with
    /// groups on the host operating system.
    Auth {},
    /// Register localhost with unet.
    ///
    /// This will register localhost as a new host on unet. The host will be
    /// identified by the specified <FULL_HOSTNAME>. <FULL_HOSTNAME> take the
    /// form <HOSTNAME>.<OWNERNAME>.unet.tech. <OWNERNAME> identifies the owner
    /// of the host through their unet username. <HOSTNAME> identifies the host
    /// within all the owner's hosts. <HOSTNAME> is not necessairly unique
    /// across users.
    ///
    /// Registration requires authorization from the proposed owner. If the
    /// proposed owner is not logged in from localhost, a registration
    /// confirmation message is broadcast to their devices. If the owner is
    /// logged in from localhost, then those credentials are used and no
    /// registration confirmation message is broadcast.
    ///
    /// The <HOSTNAME> must be unique across all hosts owned by the owner. unet
    /// provides an alternative hostname to permit registration in case of a
    /// collision. The --accept-alternative flag can be specified to
    /// automatically accept the proposed alternative.
    ///
    /// After the registration is authorized by the owner, credentials are
    /// passed back to localhost. These are stored in the subdirectory ./.unet
    /// relative to the current working directory by default. The location of
    /// where the credentials are written to can be controlled with the
    /// <OUTPUT> argument.
    ///
    /// Before performing registration, existing credentials are scanned to see
    /// if localhost is already registered. This includes looking in various
    /// directories and environment variables. The location of the credentials
    /// directory can be explicitly specified with the <INPUT> argument.
    ///
    /// Hosts are registered on unet with a set of services. Services are open
    /// source interface definitions that allow hosts to communicate through
    /// unet. The services that will be registered with localhost can be seen
    /// with `unet serve -l`.
    Register {
        /// The hostname to register localhost with
        full_hostname: String,
        /// Accept alternative hostname if provided is taken
        #[clap(long, action = clap::ArgAction::SetTrue)]
        accept_alternative: bool,
        /// Path to write credendials to
        #[clap(short, value_parser)]
        output: Option<String>,
        /// Path to read credentials from
        #[clap(short, value_parser)]
        input: Option<String>,
    },
    /// Login and connect localhost to unet
    Login {},
    /// Logout and disconnect localhost from unet
    Logout {},
    /// Initialize a new project that can be deployed to unet as a stack.
    Init {},
    /// Manage stacks deployed to unet.
    Stacks {},
    /// Build the binaries required by the current stack.
    Build {},
    /// Check the project source using each binary's target and feature flags.
    ///
    /// This will invoke `cargo check` with the target and feature arguments
    /// (--target and --features) for each binary required by the stack.
    Check {},
    /// Deploy the current stack to unet.
    ///
    /// This will first build the stack binaries first (see `unet build --help`) and
    /// deploy the stack to unet.
    Deploy {},
    /// Test the current stack.
    Test {},
    /// Manage localhost's IoT bridging service.
    ///
    /// The bridging server is used to allow locally-connected IoT devices to
    /// connect to unet even if they do not have internet access themselves.
    Bridging {},
    /// Chat with other unet users.
    Chat {},
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

enum RunError {
    RegisterError(RegisterError),
    ServeError(ServeError),
}

impl From<RegisterError> for RunError {
    fn from(err: RegisterError) -> Self {
        RunError::RegisterError(err)
    }
}

impl From<ServeError> for RunError {
    fn from(err: ServeError) -> Self {
        RunError::ServeError(err)
    }
}

async fn run(args: Args) -> Result<(), RunError> {
    // let mut args = args;
    loop {
        match &args.subcommand {
            Subcommand::Mount {} => {}
            Subcommand::Resolve {} => {}
            Subcommand::Pwd {} => {}
            Subcommand::Register {
                full_hostname,
                accept_alternative,
                output,
                input,
            } => {
                register(
                    &full_hostname,
                    accept_alternative,
                    output.as_deref(),
                    input.as_deref(),
                )
                .await
                .map_err(RunError::RegisterError)?;
            }
            Subcommand::Login {} => login().await,
            Subcommand::Logout {} => logout().await,
            Subcommand::Auth {} => {}
            Subcommand::Init {} => {}
            Subcommand::Stacks {} => {}
            Subcommand::Check {} => {
                check().await;
            }
            Subcommand::Build {} => {
                build().await;
            }
            Subcommand::Deploy {} => {
                deploy().await;
            }
            Subcommand::Test {} => test().await,
            Subcommand::Run {
                host: _,
                command: _inner_args,
            } => {
                // Get the cargo manifest path
                let cargo_manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
                // Turn it into a Path
                let cargo_manifest_path = std::path::Path::new(&cargo_manifest_path);

                println!("cargo_manifest_path: {}", cargo_manifest_path.display());

                // let prog_name = "unet".to_string();
                // args = Args::parse_from(std::iter::once(&prog_name).chain(inner_args.iter()));
                // continue;
            }
            Subcommand::Serve { .. } => {
                serve().await?;
            }
            Subcommand::Shell {} => {
                serve().await?;
            }
            Subcommand::Bridging {} => {}
            Subcommand::Chat {} => {}
        }
        break;
    }

    Ok(())
}

async fn check() {
    // Unfortunately 'cargo check' fails during cross-compile for lambda,
    // because a build.rs tries to run x86_64-linux-gnu-gcc. Can probably only
    // implement this when the build occurs in a container.

    run_build_command(&[
        "cargo",
        "check",
        "--target",
        "wasm32-unknown-unknown",
        "--features",
        "browser",
        "--bin",
        "browser",
    ])
    .await;
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
        "unet/index.html",
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
        "-t",
        "unet/template.yaml",
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

#[derive(serde::Deserialize)]
struct Metadata {
    workspace_root: String,
}

#[tokio::main]
async fn main() {
    set_env_vars();
    set_current_dir_to_project_root().await;
    let cli = Args::parse();
    run(cli).await;
}
