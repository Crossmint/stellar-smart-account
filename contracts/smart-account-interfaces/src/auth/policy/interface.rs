use soroban_sdk::{auth::Context, contractclient, contracterror, Address, Env, Vec};

use crate::auth::types::SignerKey;

/// Error variant returned by `SmartAccountPolicy` callbacks. A single
/// variant keeps the wallet-side dispatch simple — external authors can still
/// surface richer reasons via their own contract events.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum PolicyError {
    Unknown = 99,
}

#[contractclient(name = "SmartAccountPolicyClient")]
pub trait SmartAccountPolicy {
    fn on_add(env: &Env, source: Address, signer_key: SignerKey) -> Result<(), PolicyError>;
    fn on_revoke(env: &Env, source: Address, signer_key: SignerKey) -> Result<(), PolicyError>;
    fn is_authorized(
        env: &Env,
        source: Address,
        signer_key: SignerKey,
        contexts: Vec<Context>,
    ) -> Result<(), PolicyError>;
}
