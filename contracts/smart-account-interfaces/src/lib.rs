#![no_std]

pub mod account;
pub mod auth;
pub mod error;
pub mod plugin;

pub use account::{SmartAccountClient, SmartAccountInterface};
pub use auth::policy::interface::{SmartAccountPolicy, SmartAccountPolicyClient};
pub use auth::types::{
    Ed25519Signer, ExternalPolicy, MultisigMember, MultisigSigner, PendingRecoveryOpData,
    RecoveryOperation, RecoveryStorageKey, Secp256r1Signer, Signer, SignerKey, SignerPolicy,
    SignerRole, SpendTrackerKey, SpendingTracker, TokenTransferPolicy, WebauthnSigner,
};
pub use error::SmartAccountError;
pub use plugin::{SmartAccountPlugin, SmartAccountPluginClient};
