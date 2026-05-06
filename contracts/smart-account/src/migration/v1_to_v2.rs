//! Migration logic from v1.0.0 to v2.
//!
//! Handles three breaking changes:
//! 1. Secp256r1 signers (WebAuthn-based in v1) must be re-keyed to the new Webauthn signer type
//! 2. Standard signers with TimeWindowPolicy must have that policy dropped (variant removed in v2)
//! 3. ALL Standard signers require migration due to XDR layout change:
//!    v1 `Standard(Vec<SignerPolicy>)` vs v2 `Standard(Option<Vec<SignerPolicy>>, u64)`

use smart_account_interfaces::{
    Ed25519Signer, ExternalPolicy, Signer, SignerKey, SignerPolicy, SignerRole, SmartAccountError,
    WebauthnSigner,
};
use soroban_sdk::{contracttype, Env, Vec};
use storage::Storage;

use super::v1_types::{V1Signer, V1SignerKey, V1SignerPolicy, V1SignerRole};
use crate::config::{ADMIN_COUNT_KEY, PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD};

/// Data required by the migration function.
///
/// The caller must provide:
/// - `signers_to_migrate`: the list of v1 signer keys that need migration
/// - `expected_signer_count`: must equal `signers_to_migrate.len()`; catches drift
///   between the declared intent and the actual batch
/// - `expected_admin_count`: must equal the stored `ADMIN_COUNT_KEY` AND the number
///   of admins inside `signers_to_migrate`; enforces that every admin is migrated
///   in the same call
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct V1ToV2MigrationData {
    pub signers_to_migrate: Vec<V1SignerKey>,
    pub expected_signer_count: u32,
    pub expected_admin_count: u32,
}

/// Runs the v1→v2 migration for the provided signer keys.
///
/// For each key:
/// - Reads the old entry using V1 types
/// - Converts to V2 types (Secp256r1→Webauthn, TimeWindowPolicy dropped)
/// - Deletes the old storage entry
/// - Writes the new entry with V2 key and value
pub fn migrate_v1_to_v2(env: &Env, data: &V1ToV2MigrationData) -> Result<(), SmartAccountError> {
    if data.signers_to_migrate.len() != data.expected_signer_count {
        return Err(SmartAccountError::MigrationCountMismatch);
    }

    let stored_admin_count: u32 = Storage::persistent()
        .get(env, &ADMIN_COUNT_KEY)
        .unwrap_or(0);
    if stored_admin_count != data.expected_admin_count {
        return Err(SmartAccountError::MigrationAdminCountMismatch);
    }

    let mut migrated_admin_count: u32 = 0;

    for old_key in data.signers_to_migrate.iter() {
        let old_signer: V1Signer = env
            .storage()
            .persistent()
            .get(&old_key)
            .ok_or(SmartAccountError::MigrationSignerNotFound)?;

        let role = match &old_signer {
            V1Signer::Ed25519(_, role) | V1Signer::Secp256r1(_, role) => role,
        };
        if matches!(role, V1SignerRole::Admin) {
            migrated_admin_count += 1;
        }

        // Remove the old entry
        env.storage().persistent().remove(&old_key);

        // Convert and write the new entry
        let (new_key, new_signer) = convert_signer(env, &old_key, &old_signer)?;
        env.storage().persistent().set(&new_key, &new_signer);
        env.storage().persistent().extend_ttl(
            &new_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
    }

    if migrated_admin_count != data.expected_admin_count {
        return Err(SmartAccountError::MigrationAdminCountMismatch);
    }

    Ok(())
}

/// Converts a V1 signer key + value into V2 types.
fn convert_signer(
    env: &Env,
    old_key: &V1SignerKey,
    old_signer: &V1Signer,
) -> Result<(SignerKey, Signer), SmartAccountError> {
    match (old_key, old_signer) {
        // Secp256r1 → Webauthn: re-key and restructure
        (V1SignerKey::Secp256r1(_key_id), V1Signer::Secp256r1(secp_signer, v1_role)) => {
            let new_key = SignerKey::Webauthn(secp_signer.key_id.clone());
            let new_role = convert_role(env, v1_role);
            let new_signer = Signer::Webauthn(
                WebauthnSigner::new(secp_signer.key_id.clone(), secp_signer.public_key.clone()),
                new_role,
            );
            Ok((new_key, new_signer))
        }
        // Ed25519: key stays the same, only role/policies may need conversion
        (V1SignerKey::Ed25519(pk), V1Signer::Ed25519(ed_signer, v1_role)) => {
            let new_key = SignerKey::Ed25519(pk.clone());
            let new_role = convert_role(env, v1_role);
            let new_signer =
                Signer::Ed25519(Ed25519Signer::new(ed_signer.public_key.clone()), new_role);
            Ok((new_key, new_signer))
        }
        // Mismatched key/value types — should not happen with valid v1 data
        _ => Err(SmartAccountError::MigrationSignerTypeMismatch),
    }
}

/// Converts a V1 role to a V2 role, dropping TimeWindowPolicy and re-mapping
/// V1 ExternalValidatorPolicy entries onto the V2 ExternalPolicy variant
/// (different trait ABI; assumed unused in V1 deployments). Migrated Standard
/// signers get expiration = 0 and policies are wrapped in Option.
fn convert_role(env: &Env, v1_role: &V1SignerRole) -> SignerRole {
    match v1_role {
        V1SignerRole::Admin => SignerRole::Admin,
        V1SignerRole::Standard(v1_policies) => {
            let mut new_policies = Vec::new(env);
            for v1_policy in v1_policies.iter() {
                match v1_policy {
                    // TimeWindowPolicy was removed — drop it
                    V1SignerPolicy::TimeWindowPolicy(_) => {}
                    // V1 ExternalValidatorPolicy maps onto V2 ExternalPolicy.
                    V1SignerPolicy::ExternalValidatorPolicy(ext) => {
                        new_policies.push_back(SignerPolicy::ExternalPolicy(ExternalPolicy {
                            policy_address: ext.policy_address.clone(),
                        }));
                    }
                }
            }
            let policies = if new_policies.is_empty() {
                None
            } else {
                Some(new_policies)
            };
            SignerRole::Standard(policies, 0)
        }
    }
}
