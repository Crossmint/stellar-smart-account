//! Migration logic from v1.0.0 to v2.
//!
//! Handles two breaking changes:
//! 1. Secp256r1 signers (WebAuthn-based in v1) must be re-keyed to the new Webauthn signer type
//! 2. Standard signers with TimeWindowPolicy must have that policy dropped (variant removed in v2)

use soroban_sdk::{contracttype, Env, Vec};
use smart_account_interfaces::{
    Ed25519Signer, ExternalPolicy, Signer, SignerKey, SignerPolicy, SignerRole, WebauthnSigner,
};

use super::v1_types::{V1Signer, V1SignerKey, V1SignerPolicy, V1SignerRole};

/// Data required by the migration function.
/// The caller must provide the list of v1 signer keys that need migration.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1ToV2MigrationData {
    pub signers_to_migrate: Vec<V1SignerKey>,
}

/// Runs the v1→v2 migration for the provided signer keys.
///
/// For each key:
/// - Reads the old entry using V1 types
/// - Converts to V2 types (Secp256r1→Webauthn, TimeWindowPolicy dropped)
/// - Deletes the old storage entry
/// - Writes the new entry with V2 key and value
pub fn migrate_v1_to_v2(env: &Env, data: &V1ToV2MigrationData) {
    for old_key in data.signers_to_migrate.iter() {
        let old_signer: V1Signer = env
            .storage()
            .persistent()
            .get(&old_key)
            .expect("v1 signer not found during migration");

        // Remove the old entry
        env.storage().persistent().remove(&old_key);

        // Convert and write the new entry
        let (new_key, new_signer) = convert_signer(env, &old_key, &old_signer);
        env.storage().persistent().set(&new_key, &new_signer);
    }
}

/// Converts a V1 signer key + value into V2 types.
fn convert_signer(env: &Env, old_key: &V1SignerKey, old_signer: &V1Signer) -> (SignerKey, Signer) {
    match (old_key, old_signer) {
        // Secp256r1 → Webauthn: re-key and restructure
        (V1SignerKey::Secp256r1(_key_id), V1Signer::Secp256r1(secp_signer, v1_role)) => {
            let new_key = SignerKey::Webauthn(secp_signer.key_id.clone());
            let new_role = convert_role(env, v1_role);
            let new_signer = Signer::Webauthn(
                WebauthnSigner::new(secp_signer.key_id.clone(), secp_signer.public_key.clone()),
                new_role,
            );
            (new_key, new_signer)
        }
        // Ed25519: key stays the same, only role/policies may need conversion
        (V1SignerKey::Ed25519(pk), V1Signer::Ed25519(ed_signer, v1_role)) => {
            let new_key = SignerKey::Ed25519(pk.clone());
            let new_role = convert_role(env, v1_role);
            let new_signer =
                Signer::Ed25519(Ed25519Signer::new(ed_signer.public_key.clone()), new_role);
            (new_key, new_signer)
        }
        // Mismatched key/value types — should not happen with valid v1 data
        _ => panic!("mismatched v1 signer key and value types"),
    }
}

/// Converts a V1 role to a V2 role, dropping TimeWindowPolicy and re-mapping
/// ExternalValidatorPolicy.
fn convert_role(env: &Env, v1_role: &V1SignerRole) -> SignerRole {
    match v1_role {
        V1SignerRole::Admin => SignerRole::Admin,
        V1SignerRole::Standard(v1_policies) => {
            let mut new_policies = Vec::new(env);
            for v1_policy in v1_policies.iter() {
                match v1_policy {
                    // TimeWindowPolicy was removed — drop it
                    V1SignerPolicy::TimeWindowPolicy(_) => {}
                    // ExternalValidatorPolicy carries over
                    V1SignerPolicy::ExternalValidatorPolicy(ext) => {
                        new_policies.push_back(SignerPolicy::ExternalValidatorPolicy(
                            ExternalPolicy {
                                policy_address: ext.policy_address.clone(),
                            },
                        ));
                    }
                }
            }
            SignerRole::Standard(new_policies)
        }
    }
}
