use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

// ============================================================================
// Token Transfer Policy types
// ============================================================================

/// A built-in policy that restricts a Standard signer to only transferring
/// a specific SAC token, with cumulative spending limits and optional features.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TokenTransferPolicy {
    /// Unique identifier for this policy instance, used to scope the spending tracker.
    pub policy_id: BytesN<32>,
    /// The SAC token contract address this signer is allowed to call `transfer` on.
    pub token: Address,
    /// Maximum cumulative amount (in token's smallest unit) allowed per window.
    pub limit: i128,
    /// Number of seconds after which the spent amount resets. 0 = no reset (lifetime limit).
    pub reset_window_secs: u64,
    /// Allowed recipient addresses. Empty = any recipient is allowed.
    pub allowed_recipients: Vec<Address>,
    /// Unix timestamp after which this policy expires. 0 = no expiration.
    pub expiration: u64,
}

/// Tracks cumulative spending for a TokenTransferPolicy instance.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SpendingTracker {
    /// Total amount spent in the current window.
    pub spent: i128,
    /// Timestamp of the start of the current spending window.
    pub window_start: u64,
}

/// Storage key for spending tracker entries.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SpendTrackerKey {
    /// Keyed by (policy_id, signer_key) for unique per-signer-policy scoping.
    TokenSpend(BytesN<32>, SignerKey),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    Admin,
    /// Standard signer with optional policies and an optional expiration timestamp.
    /// The `u64` is a Unix timestamp after which the signer expires. 0 = no expiration.
    Standard(Option<Vec<SignerPolicy>>, u64),
    /// Recovery signer that can only perform signer management operations through
    /// a time-delayed two-phase flow (schedule → wait → execute).
    /// Recovery signers do not expire.
    /// - `u32`: delay in seconds before scheduled operations can execute
    /// - `bool`: if true, the signer can only add signers (cannot update/revoke)
    Recovery(u32, bool),
}

// ============================================================================
// Recovery operation types
// ============================================================================

/// Represents a signer management operation scheduled by a recovery signer.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryOperation {
    AddSigner(Signer),
    UpdateSigner(Signer),
    RevokeSigner(SignerKey),
}

/// Storage key for pending recovery operations.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryStorageKey {
    /// Maps an OZ timelock operation_id to its pending recovery data.
    PendingOp(BytesN<32>),
}

/// Data stored for each pending recovery operation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingRecoveryOpData {
    /// The signer management operation to perform.
    pub operation: RecoveryOperation,
    /// The recovery signer that scheduled the operation.
    pub scheduled_by: SignerKey,
    /// Unix timestamp when the operation was scheduled.
    pub scheduled_at: u64,
    /// The salt used when scheduling, needed to rebuild the OZ Operation for execution.
    pub salt: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    ExternalValidatorPolicy(ExternalPolicy),
    TokenTransferPolicy(TokenTransferPolicy),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPolicy {
    pub policy_address: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(BytesN<65>),
    Webauthn(Bytes),
    Multisig(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct WebauthnSigner {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MultisigMember {
    Ed25519(Ed25519Signer),
    Secp256r1(Secp256r1Signer),
    Webauthn(WebauthnSigner),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MultisigSigner {
    pub id: BytesN<32>,
    pub members: Vec<MultisigMember>,
    pub threshold: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
    Webauthn(WebauthnSigner, SignerRole),
    Multisig(MultisigSigner, SignerRole),
}

impl Ed25519Signer {
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

impl Secp256r1Signer {
    pub fn new(public_key: BytesN<65>) -> Self {
        Self { public_key }
    }
}

impl WebauthnSigner {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

impl MultisigSigner {
    pub fn new(id: BytesN<32>, members: Vec<MultisigMember>, threshold: u32) -> Self {
        Self {
            id,
            members,
            threshold,
        }
    }
}

impl Signer {
    pub fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
            Signer::Secp256r1(_, role) => role.clone(),
            Signer::Webauthn(_, role) => role.clone(),
            Signer::Multisig(_, role) => role.clone(),
        }
    }

    /// Returns the expiration timestamp (0 = no expiration).
    /// Admin and Recovery signers always return 0 (never expire).
    pub fn expiration(&self) -> u64 {
        match self.role() {
            SignerRole::Standard(_, expiration) => expiration,
            SignerRole::Admin | SignerRole::Recovery(_, _) => 0,
        }
    }

    /// Checks whether this signer has expired based on the current ledger timestamp.
    pub fn is_expired(&self, env: &Env) -> bool {
        let exp = self.expiration();
        exp > 0 && env.ledger().timestamp() > exp
    }
}

impl From<Ed25519Signer> for SignerKey {
    fn from(signer: Ed25519Signer) -> Self {
        SignerKey::Ed25519(signer.public_key.clone())
    }
}

impl From<Secp256r1Signer> for SignerKey {
    fn from(signer: Secp256r1Signer) -> Self {
        SignerKey::Secp256r1(signer.public_key.clone())
    }
}

impl From<WebauthnSigner> for SignerKey {
    fn from(signer: WebauthnSigner) -> Self {
        SignerKey::Webauthn(signer.key_id.clone())
    }
}

impl From<MultisigMember> for SignerKey {
    fn from(member: MultisigMember) -> Self {
        match member {
            MultisigMember::Ed25519(signer) => signer.into(),
            MultisigMember::Secp256r1(signer) => signer.into(),
            MultisigMember::Webauthn(signer) => signer.into(),
        }
    }
}

impl From<MultisigSigner> for SignerKey {
    fn from(signer: MultisigSigner) -> Self {
        SignerKey::Multisig(signer.id.clone())
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
            Signer::Secp256r1(signer, _) => signer.into(),
            Signer::Webauthn(signer, _) => signer.into(),
            Signer::Multisig(signer, _) => signer.into(),
        }
    }
}
