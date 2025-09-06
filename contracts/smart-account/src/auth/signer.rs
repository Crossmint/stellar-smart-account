use crate::auth::permissions::{AuthorizationCheck, SignerRole};
use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
pub use smart_account_interfaces::{Ed25519Signer, Secp256r1Signer, Signer, SignerKey};
use soroban_sdk::Vec;
use soroban_sdk::{auth::Context, BytesN, Env};

impl SignatureVerifier for Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            Signer::Ed25519(signer, _) => signer.verify(env, payload, proof),
            Signer::Secp256r1(signer, _) => signer.verify(env, payload, proof),
        }
    }
}

impl AuthorizationCheck for Signer {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        self.role().is_authorized(env, contexts)
    }
}

pub trait SignerExt {
    fn role(&self) -> SignerRole;
}

impl SignerExt for Signer {
    fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
            Signer::Secp256r1(_, role) => role.clone(),
        }
    }
}

pub fn signer_key_of(signer: &Signer) -> SignerKey {
    match signer {
        Signer::Ed25519(s, _) => SignerKey::Ed25519(s.public_key.clone()),
        Signer::Secp256r1(s, _) => SignerKey::Secp256r1(s.key_id.clone()),
    }
}
