use soroban_sdk::{
    auth::Context, contractclient, contracterror, contracttype, Address, Bytes, BytesN, Env, Vec,
};

#[contractclient(name = "SmartAccountPolicyClient")]
pub trait SmartAccountPolicy {
    fn on_add(env: &Env, source: Address);
    fn on_revoke(env: &Env, source: Address);
    fn is_authorized(env: &Env, source: Address, contexts: Vec<Context>) -> bool;
}

// === Shared data types used by the SmartAccount interface ===

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SmartAccountError {
    // === Initialization Errors (0-9) ===
    AlreadyInitialized = 0,
    NotInitialized = 1,
    AccountInitializationFailed = 2,

    // === Storage Errors (10-19) ===
    StorageEntryNotFound = 10,
    StorageEntryAlreadyExists = 11,

    // === Signer Management Errors (20-39) ===
    NoSigners = 20,
    SignerAlreadyExists = 21,
    SignerNotFound = 22,
    SignerExpired = 23,
    CannotRevokeAdminSigner = 24,
    CannotDowngradeLastAdmin = 25,
    MaxSignersReached = 26,

    // === Authentication & Signature Errors (40-59) ===
    MatchingSignatureNotFound = 40,
    SignatureVerificationFailed = 41,
    InvalidProofType = 42,
    NoProofsInAuthEntry = 43,
    ClientDataJsonIncorrectChallenge = 44,
    InvalidWebauthnClientDataJson = 45,

    // === Permission Errors (60-79) ===
    InsufficientPermissions = 60,
    InsufficientPermissionsOnCreation = 61,

    // === Policy Errors (80-99) ===
    InvalidPolicy = 80,
    InvalidTimeRange = 81,
    InvalidNotAfterTime = 82,
    PolicyClientInitializationError = 83,

    // === Plugin Errors (100-119) ===
    PluginNotFound = 100,
    PluginAlreadyInstalled = 101,
    PluginInitializationFailed = 102,
    PluginOnAuthFailed = 103,

    // === Generic Errors (1000+) ===
    NotFound = 1000,
}

// No generic self-From impl needed; core already provides From<T> for T

// This defines the roles that a configured signer can have
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    Admin,
    Standard(Vec<SignerPolicy>),
}

// Main policy enum that wraps the individual policies
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    ExternalValidatorPolicy(ExternalPolicy),
}

// Time-based policy removed

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPolicy {
    pub policy_address: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
}

// === Inherent constructors and helpers for moved data types ===

impl Ed25519Signer {
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

impl Secp256r1Signer {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

impl Signer {
    pub fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
            Signer::Secp256r1(_, role) => role.clone(),
        }
    }
}

impl From<Ed25519Signer> for SignerKey {
    fn from(signer: Ed25519Signer) -> Self {
        SignerKey::Ed25519(signer.public_key.clone())
    }
}

impl From<Secp256r1Signer> for SignerKey {
    fn from(signer: Secp256r1Signer) -> Self {
        SignerKey::Secp256r1(signer.key_id.clone())
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
            Signer::Secp256r1(signer, _) => signer.into(),
        }
    }
}

// Map external crate errors into SmartAccountError so downstream crates can use `?`
impl From<initializable::Error> for SmartAccountError {
    fn from(e: initializable::Error) -> Self {
        match e {
            initializable::Error::AlreadyInitialized => SmartAccountError::AlreadyInitialized,
            initializable::Error::NotInitialized => SmartAccountError::NotInitialized,
        }
    }
}

impl From<storage::Error> for SmartAccountError {
    fn from(e: storage::Error) -> Self {
        match e {
            storage::Error::NotFound => SmartAccountError::StorageEntryNotFound,
            storage::Error::AlreadyExists => SmartAccountError::StorageEntryAlreadyExists,
        }
    }
}
