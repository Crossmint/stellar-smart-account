use crate::auth::signer::{Signer, SignerKey};
use soroban_sdk::{contracttype, Address, String};

#[contracttype]
#[derive(Clone)]
pub struct SignerAddedEvent {
    pub signer_key: SignerKey,
    pub signer: Signer,
}

impl From<Signer> for SignerAddedEvent {
    fn from(signer: Signer) -> Self {
        SignerAddedEvent {
            signer_key: signer.clone().into(),
            signer,
        }
    }
}

#[contracttype]
#[derive(Clone)]
pub struct SignerUpdatedEvent {
    pub signer_key: SignerKey,
    pub new_signer: Signer,
}

impl From<Signer> for SignerUpdatedEvent {
    fn from(signer: Signer) -> Self {
        SignerUpdatedEvent {
            signer_key: signer.clone().into(),
            new_signer: signer,
        }
    }
}

#[contracttype]
#[derive(Clone)]
pub struct SignerRevokedEvent {
    pub signer_key: SignerKey,
    pub revoked_signer: Signer,
}

impl From<Signer> for SignerRevokedEvent {
    fn from(signer: Signer) -> Self {
        SignerRevokedEvent {
            signer_key: signer.clone().into(),
            revoked_signer: signer,
        }
    }
}

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

#[contracttype]
#[derive(Clone)]
pub struct PluginUninstallFailedEvent {
    pub plugin: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct PluginAuthFailedEvent {
    pub plugin: Address,
    pub error: String,
}

#[contracttype]
#[derive(Clone)]
pub struct PolicyCallbackFailedEvent {
    pub policy_address: Address,
}
