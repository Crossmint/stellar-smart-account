use crate::auth::permissions::{AuthorizationCheck, SignerRole};
use crate::auth::proof::SignatureProofs;
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::SignatureVerifier as _;
use crate::error::Error;
use soroban_sdk::{auth::Context, crypto::Hash, Env, Vec};
use storage::Storage;

///
///
/// 3. **Permission Checking**: Each signer's permissions are evaluated against the requested operations
///
/// - **Admin**: Highest priority, can authorize most operations
pub struct AuthorizationService;

impl AuthorizationService {
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
    /// * `Err(Error::NoProofsInAuthEntry)` if no signatures provided
    /// * `Err(Error::SignerNotFound)` if a signing key is not registered
    /// * `Err(Error::SignatureVerificationFailed)` if signature validation fails
    /// * `Err(Error::InsufficientPermissions)` if no signer can authorize the operations
    ///
    pub fn check_authorization(
        env: &Env,
        signature_payload: Hash<32>,
        auth_payloads: &SignatureProofs,
        auth_contexts: &Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::default();
        let SignatureProofs(proof_map) = auth_payloads;

        // Ensure we have at least one authorization proof
        if proof_map.is_empty() {
            return Err(Error::NoProofsInAuthEntry);
        }

        // Step 1: Verify signatures and group by role priority for efficient authorization
        let mut admin_signers = Vec::new(env);
        let mut standard_signers = Vec::new(env);

        // Verify signatures while preprocessing by role
        for (signer_key, proof) in proof_map.iter() {
            let signer = storage
                .get::<SignerKey, Signer>(env, &signer_key)
                .ok_or(Error::SignerNotFound)?;
            signer.verify(env, &signature_payload.to_bytes(), &proof)?;

            // Group by role during validation
            match signer.role() {
                SignerRole::Admin => admin_signers.push_back(signer),
                SignerRole::Standard(_) => standard_signers.push_back(signer),
            }
        }

        // Step 2: Check authorization in priority order with early returns
        // Admin signers first (highest priority)
        for signer in admin_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
                return Ok(()); // Early return on first authorized admin
            }
        }

        // Standard signers second
        for signer in standard_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
                return Ok(()); // Early return on first authorized standard
            }
        }

        // No authorized signer found
        Err(Error::InsufficientPermissions)
    }
}
