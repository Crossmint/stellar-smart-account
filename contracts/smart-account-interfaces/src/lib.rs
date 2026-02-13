#![no_std]

pub mod account;
pub mod auth;
pub mod error;
pub mod plugin;

pub use account::{SmartAccountClient, SmartAccountInterface};
pub use auth::policy::interface::{SmartAccountPolicy, SmartAccountPolicyClient};
pub use auth::types::{
    Ed25519Signer, ExternalPolicy, MultisigMember, MultisigSigner, Secp256r1Signer, Signer,
    SignerKey, SignerPolicy, SignerRole,
};
pub use error::SmartAccountError;
pub use plugin::{SmartAccountPlugin, SmartAccountPluginClient};
