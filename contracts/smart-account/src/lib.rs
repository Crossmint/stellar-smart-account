#![no_std]

pub mod account;
pub mod auth;
pub mod error;
pub mod interface;
pub mod module;

// Re-export key types for external use and bindings generation
pub use auth::permissions::{SignerPolicy, SignerRole};
pub use auth::proof::{SignatureProofs, SignerProof};
pub use auth::signer::{Signer, SignerKey};
pub use error::Error;

#[cfg(test)]
mod tests;
