#![no_std]

pub mod account;
pub mod auth;
pub mod config;
pub mod constants;
pub mod error;
pub mod events;
pub mod plugin;
pub mod utils;

// Re-export key types for external use and bindings generation
pub use auth::policy::SmartAccountPolicy;
pub use auth::proof::{SignatureProofs, SignerProof};
pub use error::Error;
pub use plugin::SmartAccountPlugin;
pub use smart_account_interfaces::{Signer, SignerKey};
pub use smart_account_interfaces::{SignerPolicy, SignerRole};

#[cfg(test)]
mod tests;
