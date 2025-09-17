use crate::auth::permissions::AuthorizationCheck;
use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::{Ed25519Signer, Secp256r1Signer, Signer};
use soroban_sdk::Vec;
use soroban_sdk::{auth::Context, BytesN, Env};

impl SignatureVerifier for Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            Signer::Ed25519(signer, _) => Ed25519Signer {
                public_key: signer.public_key.clone(),
            }
            .verify(env, payload, proof),
            Signer::Secp256r1(signer, _) => Secp256r1Signer {
                key_id: signer.key_id.clone(),
                public_key: signer.public_key.clone(),
            }
            .verify(env, payload, proof),
        }
    }
}

impl AuthorizationCheck for Signer {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        self.role().is_authorized(env, contexts)
    }
}
