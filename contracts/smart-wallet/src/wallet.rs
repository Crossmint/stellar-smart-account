use crate::auth::permissions::SignerRole;
use crate::auth::permissions::{AuthorizationCheck, PolicyValidator};
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::SignatureVerifier as _;
use crate::error::Error;
use crate::interface::SmartWalletInterface;
use initializable::{only_not_initialized, Initializable};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    log, panic_with_error, Env, Map, Vec,
};
use storage::Storage;
use upgradeable::{SmartWalletUpgradeable, SmartWalletUpgradeableAuth};

use crate::auth::proof::SignatureProofs;

/// SmartWallet is a multi-signature wallet contract that provides enhanced security
/// through role-based access control and policy-based authorization.
///
/// The wallet supports different signers with different signer roles (Admin, Standard, Restricted) with customizable
/// policies for fine-grained permission management.
#[contract]
pub struct SmartWallet;

// Implements SmartWalletUpgradeable trait to allow the contract to be upgraded
// by authorized signers through the upgrade mechanism
#[contractimpl]
impl SmartWalletUpgradeable for SmartWallet {}

impl SmartWalletUpgradeableAuth for SmartWallet {
    fn _require_auth_upgrade(e: &Env) {
        e.current_contract_address().require_auth();
    }
}

// Implements Initializable trait to allow the contract to be initialized.
// that allows the deployer to set the initial signer configuration without
// an explicit authorization for those signers
impl Initializable for SmartWallet {}

// ============================================================================
// SmartWalletInterface implementation
// ============================================================================

/// Implementation of the SmartWalletInterface trait that defines the public interface
/// for all administrative operations on the smart wallet.
///
/// # Arguments
/// * `env` - The contract environment
/// * `signers` - A vector of initial signers with their roles and policies
///
/// # Panics
///
/// If a initialization precondition is not met, the contract will panic with an error.
/// If the wallet is already initialized, the contract will panic with an error.
#[contractimpl]
impl SmartWalletInterface for SmartWallet {
    fn __constructor(env: Env, signers: Vec<Signer>) {
        only_not_initialized!(&env);

        // Check that there is at least one admin signer to prevent the contract from being locked out.
        if !signers.iter().any(|s| s.role() == SignerRole::Admin) {
            panic_with_error!(env, Error::InsufficientPermissionsOnCreation);
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
            SmartWallet::add_signer(&env, signer).unwrap_or_else(|e| panic_with_error!(env, e));
        });

        SmartWallet::initialize(&env).unwrap_or_else(|e| panic_with_error!(env, e));
    }

    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        if Self::is_initialized(env) {
            env.current_contract_address().require_auth();
        }
        Storage::default().store::<SignerKey, Signer>(
            env,
            &signer.clone().into(),
            &signer.clone(),
        )?;
        Ok(())
    }

    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        if Self::is_initialized(env) {
            env.current_contract_address().require_auth();
        }
        Storage::default().update::<SignerKey, Signer>(
            env,
            &signer.clone().into(),
            &signer.clone(),
        )?;
        Ok(())
    }

    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error> {
        if Self::is_initialized(env) {
            env.current_contract_address().require_auth();
        }
        Storage::default().delete::<SignerKey>(env, &signer_key)?;
        Ok(())
    }
}

// ============================================================================
// CustomAccountInterface implementation
// ============================================================================

/// Implementation of Soroban's CustomAccountInterface for smart wallet authorization.
///
/// This provides the custom authorization logic that the Soroban runtime uses
/// to verify whether operations are authorized by the wallet's signers.
#[contractimpl]
impl CustomAccountInterface for SmartWallet {
    /// The signature type used for authorization proofs.
    /// Contains a map of signer keys to their corresponding signature proofs.
    type Signature = SignatureProofs;
    type Error = Error;

    /// Custom authorization function invoked by the Soroban runtime.
    ///
    /// This function implements the wallet's authorization logic:
    /// 1. Verifies that all provided signatures are cryptographically valid
    /// 2. Checks that at least one authorized signer has approved each operation
    /// 3. Ensures signers have the required permissions for the requested operations
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
        for (signer_key, proof) in proof_map.iter() {
            let signer = match storage.get::<SignerKey, Signer>(&env, &signer_key.clone()) {
                Some(signer) => signer,
                None => {
                    log!(&env, "Signer not found {:?}", signer_key);
                    return Err(Error::SignerNotFound);
                }
            };
            signer.verify(&env, &signature_payload.to_bytes(), &proof)?;
            verified_signers.set(signer_key.clone(), signer);
        }

        // Step 2: Check authorization for each operation context using cached signers
        // Ensure that for each operation, at least one signer has the required permissions
        for context in auth_contexts.iter() {
            if !proof_map.iter().any(|(signer_key, _)| {
                let signer = verified_signers.get(signer_key.clone()).unwrap(); // Safe to unwrap - we verified signer exists above
                signer.role().is_authorized(&env, &context)
            }) {
                return Err(Error::InsufficientPermissions);
            }
        }

        Ok(())
    }
}
