//! V1-compatible type definitions for reading v1.0.0 on-chain storage data.
//!
//! These types produce the same Soroban XDR encoding as the original v1.0.0 types,
//! allowing the migration logic to deserialize old storage entries. The types are
//! intentionally self-contained to avoid coupling with current type definitions.
//!
//! Key differences from current types:
//! - `SignerKey::Secp256r1` holds `Bytes` (key_id), not `BytesN<65>` (public_key)
//! - `Secp256r1Signer` has both `key_id` and `public_key` fields (was WebAuthn-based)
//! - `SignerPolicy` includes `TimeWindowPolicy` variant (removed in v2)

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Vec};

// ============================================================================
// Signer key (used as persistent storage key)
// ============================================================================

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum V1SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes), // key_id, not public_key
}

// ============================================================================
// Signer structs
// ============================================================================

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1Ed25519Signer {
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1Secp256r1Signer {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

// ============================================================================
// Policies
// ============================================================================

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1TimeBasedPolicy {
    pub not_before: u64,
    pub not_after: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1ExternalPolicy {
    pub policy_address: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum V1SignerPolicy {
    TimeWindowPolicy(V1TimeBasedPolicy),
    ExternalValidatorPolicy(V1ExternalPolicy),
}

// ============================================================================
// Roles and top-level signer enum
// ============================================================================

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum V1SignerRole {
    Admin,
    Standard(Vec<V1SignerPolicy>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum V1Signer {
    Ed25519(V1Ed25519Signer, V1SignerRole),
    Secp256r1(V1Secp256r1Signer, V1SignerRole),
}
