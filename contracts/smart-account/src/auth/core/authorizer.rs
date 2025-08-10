/// Authorization service that verifies proofs and enforces role/policy checks.
use crate::auth::permissions::{AuthorizationCheck, SignerRole};
use crate::auth::proof::SignatureProofs;
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::SignatureVerifier as _;
use crate::error::Error;
use soroban_sdk::{auth::Context, crypto::Hash, Env, Vec};
use storage::Storage;

pub struct Authorizer;

impl Authorizer {
    pub fn check(
        env: &Env,
        signature_payload: Hash<32>,
        auth_payloads: &SignatureProofs,
        auth_contexts: &Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::default();
        let SignatureProofs(proof_map) = auth_payloads;

        if proof_map.is_empty() {
            return Err(Error::NoProofsInAuthEntry);
        }

        let mut admin_signers = Vec::new(env);
        let mut standard_signers = Vec::new(env);

        for (signer_key, proof) in proof_map.iter() {
            let signer = storage
                .get::<SignerKey, Signer>(env, &signer_key)
                .ok_or(Error::SignerNotFound)?;
            signer.verify(env, &signature_payload.to_bytes(), &proof)?;

            match signer.role() {
                SignerRole::Admin => admin_signers.push_back(signer),
                SignerRole::Standard(_) => standard_signers.push_back(signer),
            }
        }

        for signer in admin_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
                return Ok(());
            }
        }

        for signer in standard_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
                return Ok(());
            }
        }

        Err(Error::InsufficientPermissions)
    }
}
