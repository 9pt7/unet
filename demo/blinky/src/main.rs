trait Light {}

trait WebPage {}

enum Error {
    InvalidCargoEnvironment,
}

// Optionally, if you want to provide a more detailed implementation:
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidCargoEnvironment => write!(f, "Invalid cargo environment"),
        }
    }
}

#[derive(Debug)]
struct CargoEnvVars {
    cargo: std::path::PathBuf,
    cargo_manifest_dir: std::path::PathBuf,
    cargo_pkg_version: String,
    cargo_pkg_name: String,
    cargo_primary_package: String,
}

fn get_env_var_path(name: &str) -> Result<std::path::PathBuf, Error> {
    let path = std::env::var(name).map_err(|_| Error::InvalidCargoEnvironment {})?;
    Ok(std::path::PathBuf::from(path))
}

fn get_env_var_string(name: &str) -> Result<String, Error> {
    Ok(std::env::var(name).unwrap())
}

fn main() -> Result<(), Error> {
    // cli![Light, WebPage];

    let cargo_env_vars = CargoEnvVars {
        cargo: get_env_var_path("CARGO")?,
        cargo_manifest_dir: get_env_var_path("CARGO_MANIGEST_DIR")?,
        cargo_pkg_version: get_env_var_string("CARGO_PKG_VERSION")?,
        cargo_pkg_name: get_env_var_string("CARGO_PKG_NAME")?,
        cargo_primary_package: get_env_var_string("CARGO_PRIMARY_PACKAGE")?,
    };

    dbg!(cargo_env_vars);

    Ok(())
}
