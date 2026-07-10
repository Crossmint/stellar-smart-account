use smart_account_interfaces::{Signer, SignerKey};
use soroban_sdk::{contractevent, Address, String};

#[contractevent(topics = ["signer", "added"])]
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

#[contractevent(topics = ["signer", "updated"])]
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

#[contractevent(topics = ["signer", "revoked"])]
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

#[contractevent(topics = ["plugin", "installed"])]
#[derive(Clone)]
pub struct PluginInstalledEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "uninst"])]
#[derive(Clone)]
pub struct PluginUninstalledEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "uninsterr"])]
#[derive(Clone)]
pub struct PluginUninstallFailedEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "autherr"])]
#[derive(Clone)]
pub struct PluginAuthFailedEvent {
    #[topic]
    pub plugin: Address,
    pub error: String,
}

#[contractevent(topics = ["policy", "cbfailed"])]
#[derive(Clone)]
pub struct PolicyCallbackFailedEvent {
    pub policy_address: Address,
}

/// Emitted when a two-phase upgrade begins; data is the contract's own address.
#[contractevent(topics = ["UPGRADE_STARTED"], data_format = "single-value")]
#[derive(Clone)]
pub struct UpgradeStartedEvent {
    pub contract: Address,
}

/// Emitted when a two-phase upgrade completes; data is the contract's own address.
#[contractevent(topics = ["UPGRADE_COMPLETED"], data_format = "single-value")]
#[derive(Clone)]
pub struct UpgradeCompletedEvent {
    pub contract: Address,
}
