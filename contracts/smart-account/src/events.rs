use crate::auth::signer::{Signer, SignerKey};
use soroban_sdk::{contracttype, Address};

/*
 * Signer events
 */

#[contracttype]
#[derive(Clone)]
pub struct SignerAddedEvent {
    pub signer_key: SignerKey,
    pub signer: Signer,
}

#[contracttype]
#[derive(Clone)]
pub struct SignerUpdatedEvent {
    pub signer_key: SignerKey,
    pub new_signer: Signer,
}

#[contracttype]
#[derive(Clone)]
pub struct SignerRevokedEvent {
    pub signer_key: SignerKey,
    pub revoked_signer: Signer,
}

/*
 * Plugin events
 */

#[contracttype]
#[derive(Clone)]
pub struct PluginInstalledEvent {
    pub plugin: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct PluginUninstalledEvent {
    pub plugin: Address,
}
