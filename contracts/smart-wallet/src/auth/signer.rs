use crate::auth::signature::SignerProof;
use crate::auth::signers::ed25519::Ed25519Signer;
use crate::auth::signers::SignerVerification;
use crate::error::Error;
use soroban_sdk::{contracttype, BytesN, Env};

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerExpiration(pub Option<u32>);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer),
}

impl SignerVerification for Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            Signer::Ed25519(signer) => signer.verify(env, payload, proof),
        }
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer) => signer.into(),
        }
    }
}
