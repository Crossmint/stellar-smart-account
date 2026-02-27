use smart_account_interfaces::{RecoveryOperation, Signer, SignerKey};
use soroban_sdk::{contractevent, Address, BytesN, String};

#[contractevent(topics = ["signer", "added"])]
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
pub struct PluginInstalledEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "uninstalled"])]
pub struct PluginUninstalledEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "uninstall_failed"])]
pub struct PluginUninstallFailedEvent {
    pub plugin: Address,
}

#[contractevent(topics = ["plugin", "auth_failed"])]
pub struct PluginAuthFailedEvent {
    #[topic]
    pub plugin: Address,
    pub error: String,
}

#[contractevent(topics = ["policy", "callback_failed"])]
pub struct PolicyCallbackFailedEvent {
    pub policy_address: Address,
}

#[contractevent(topics = ["recovery", "scheduled"])]
pub struct RecoveryScheduledEvent {
    pub operation_id: BytesN<32>,
    pub operation: RecoveryOperation,
    pub scheduled_by: SignerKey,
    pub execute_after: u64,
}

#[contractevent(topics = ["recovery", "executed"])]
pub struct RecoveryExecutedEvent {
    pub operation_id: BytesN<32>,
    pub operation: RecoveryOperation,
}

#[contractevent(topics = ["recovery", "cancelled"])]
pub struct RecoveryCancelledEvent {
    pub operation_id: BytesN<32>,
}

