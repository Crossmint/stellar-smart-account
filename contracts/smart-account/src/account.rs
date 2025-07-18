use crate::auth::permissions::SignerRole;
use crate::auth::permissions::{AuthorizationCheck, PolicyValidator};
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::SignatureVerifier as _;
use crate::error::Error;
use crate::interface::SmartAccountInterface;
use initializable::{only_not_initialized, Initializable};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl, contracttype,
    crypto::Hash,
    log, panic_with_error, symbol_short, Env, Vec,
};
use storage::Storage;
use upgradeable::{SmartAccountUpgradeable, SmartAccountUpgradeableAuth};

use crate::auth::proof::SignatureProofs;

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

/// SmartAccount is a multi-signature account contract that provides enhanced security
/// through role-based access control and policy-based authorization.
///
/// The account supports different signers with different signer roles (Admin, Standard, Restricted) with customizable
/// policies for fine-grained permission management.
#[contract]
pub struct SmartAccount;

// Implements SmartAccountUpgradeable trait to allow the contract to be upgraded
// by authorized signers through the upgrade mechanism
upgradeable::impl_upgradeable!(SmartAccount);

impl SmartAccountUpgradeableAuth for SmartAccount {
    fn _require_auth_upgrade(e: &Env) {
        e.current_contract_address().require_auth();
    }
}

// Implements Initializable trait to allow the contract to be initialized.
// that allows the deployer to set the initial signer configuration without
// an explicit authorization for those signers
impl Initializable for SmartAccount {}

impl SmartAccount {
    /// Only requires authorization if the contract is already initialized.
    fn require_auth_if_initialized(env: &Env) {
        if Self::is_initialized(env) {
            env.current_contract_address().require_auth();
        }
    }
}

// ============================================================================
// SmartAccountInterface implementation
// ============================================================================

/// Implementation of the SmartAccountInterface trait that defines the public interface
/// for all administrative operations on the smart account.
///
/// # Arguments
/// * `env` - The contract environment
/// * `signers` - A vector of initial signers with their roles and policies
///
/// # Panics
///
/// If a initialization precondition is not met, the contract will panic with an error.
/// If the account is already initialized, the contract will panic with an error.
#[contractimpl]
impl SmartAccountInterface for SmartAccount {
    fn __constructor(env: Env, signers: Vec<Signer>) {
        only_not_initialized!(&env);

        // Check that there is at least one admin signer to prevent the contract from being locked out.
        if !signers.iter().any(|s| s.role() == SignerRole::Admin) {
            panic_with_error!(env, Error::InsufficientPermissionsOnCreation);
        }

        let mut seen_signer_keys = Vec::new(&env);
        for signer in signers.iter() {
            let signer_key: SignerKey = signer.clone().into();
            if seen_signer_keys.contains(&signer_key) {
                panic_with_error!(env, Error::SignerAlreadyExists);
            }
            seen_signer_keys.push_back(signer_key);
        }

        signers.iter().for_each(|signer| {
            // If it's a restricted signer, we check that the policies are valid.
            if let SignerRole::Restricted(policies) = signer.role() {
                for policy in policies {
                    policy
                        .check(&env)
                        .unwrap_or_else(|e| panic_with_error!(env, e));
                }
            }
            SmartAccount::add_signer(&env, signer).unwrap_or_else(|e| panic_with_error!(env, e));
        });

        SmartAccount::initialize(&env).unwrap_or_else(|e| panic_with_error!(env, e));
    }

    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);
        let key = signer.clone().into();
        Storage::default().store::<SignerKey, Signer>(env, &key, &signer)?;

        let event = SignerAddedEvent {
            signer_key: key.clone(),
            signer: signer.clone(),
        };
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("added")), event);

        Ok(())
    }

    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);
        let key = signer.clone().into();

        let storage = Storage::default();
        storage.update::<SignerKey, Signer>(env, &key, &signer)?;

        let event = SignerUpdatedEvent {
            signer_key: key.clone(),
            new_signer: signer.clone(),
        };
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("updated")), event);

        Ok(())
    }

    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::default();

        let signer_to_revoke = storage
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(Error::SignerNotFound)?;

        if signer_to_revoke.role() == SignerRole::Admin {
            return Err(Error::CannotRevokeAdminSigner);
        }

        storage.delete::<SignerKey>(env, &signer_key)?;

        let event = SignerRevokedEvent {
            signer_key: signer_key.clone(),
            revoked_signer: signer_to_revoke.clone(),
        };
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("revoked")), event);

        Ok(())
    }
}

// ============================================================================
// CustomAccountInterface implementation
// ============================================================================

/// Implementation of Soroban's CustomAccountInterface for smart account authorization.
///
/// This provides the custom authorization logic that the Soroban runtime uses
/// to verify whether operations are authorized by the account's signers.
#[contractimpl]
impl CustomAccountInterface for SmartAccount {
    /// The signature type used for authorization proofs.
    /// Contains a map of signer keys to their corresponding signature proofs.
    type Signature = SignatureProofs;
    type Error = Error;

    /// Custom authorization function invoked by the Soroban runtime.
    ///
    /// This function implements the account's authorization logic with optimizations for Stellar costs:
    /// 1. Verifies that all provided signatures are cryptographically valid
    /// 2. Checks that at least one authorized signer has approved each operation
    /// 3. Ensures signers have the required permissions for the requested operations
    ///
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `signature_payload` - Hash of the data that was signed
    /// * `auth_payloads` - Map of signer keys to their signature proofs
    /// * `auth_contexts` - List of operations being authorized
    ///
    /// # Returns
    /// * `Ok(())` if authorization succeeds
    /// * `Err(Error)` if authorization fails for any reason
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        auth_payloads: SignatureProofs,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::default();
        let SignatureProofs(proof_map) = auth_payloads;

        // Ensure we have at least one authorization proof
        if proof_map.is_empty() {
            return Err(Error::NoProofsInAuthEntry);
        }

        // Step 1: Verify all provided signatures are cryptographically valid and cache signers
        let mut verified_signers = soroban_sdk::Map::new(&env);

        for (signer_key, _) in proof_map.iter() {
            if !storage.has(&env, &signer_key) {
                log!(&env, "Signer not found {:?}", signer_key);
                return Err(Error::SignerNotFound);
            }
        }

        // Now verify signatures and cache signers
        for (signer_key, proof) in proof_map.iter() {
            let signer = storage.get::<SignerKey, Signer>(&env, &signer_key).unwrap(); // Safe after has() check
            signer.verify(&env, &signature_payload.to_bytes(), &proof)?;
            verified_signers.set(signer_key.clone(), signer);
        }

        // Step 2: Check authorization for each operation context using cached signers
        for context in auth_contexts.iter() {
            let mut context_authorized = false;
            for (signer_key, _) in proof_map.iter() {
                let signer = verified_signers.get(signer_key.clone()).unwrap(); // Safe to unwrap - we verified signer exists above
                if signer.role().is_authorized(&env, &context) {
                    context_authorized = true;
                    break; // Early exit when authorization found
                }
            }
            if !context_authorized {
                return Err(Error::InsufficientPermissions);
            }
        }

        Ok(())
    }
}
