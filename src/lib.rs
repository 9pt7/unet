#[cfg(feature = "browser")]
pub mod browser;
pub mod cloud;
pub mod platforms;

#[cfg(feature = "aws")]
pub use cloud::lambda_main;
