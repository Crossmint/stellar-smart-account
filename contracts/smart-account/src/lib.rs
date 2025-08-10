#![no_std]

pub mod account;
pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod interface;
pub mod plugin;

// Re-export key types for external use and bindings generation
pub use auth::permissions::{SignerPolicy, SignerRole};
pub use auth::policy::SmartAccountPolicy;
pub use auth::proof::{SignatureProofs, SignerProof};
pub use auth::signer::{Signer, SignerKey};
pub use error::Error;
pub use plugin::SmartAccountPlugin;

#[cfg(test)]
mod tests;
