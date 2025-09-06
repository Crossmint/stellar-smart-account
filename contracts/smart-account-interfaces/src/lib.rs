#![no_std]

pub mod account;
pub mod plugin;
pub mod policy;

pub use account::{SmartAccountClient, SmartAccountInterface};
pub use plugin::{SmartAccountPlugin, SmartAccountPluginClient};
pub use policy::{
    Ed25519Signer, ExternalPolicy, Secp256r1Signer, Signer, SignerKey, SignerPolicy, SignerRole,
    SmartAccountError, SmartAccountPolicy, SmartAccountPolicyClient,
};
