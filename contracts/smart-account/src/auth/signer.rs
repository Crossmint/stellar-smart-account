use crate::auth::permissions::{AuthorizationCheck, SignerRole};
use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::auth::signers::{Ed25519Signer, Secp256r1Signer};
use crate::error::Error;
use soroban_sdk::Vec;
use soroban_sdk::{auth::Context, contracttype, Bytes, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
}

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

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
            Signer::Secp256r1(signer, _) => signer.into(),
        }
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
