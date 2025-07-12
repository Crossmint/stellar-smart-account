use crate::auth::permissions::{PermissionsCheck, SignerRole};
use crate::auth::proof::SignerProof;
use crate::auth::signers::Ed25519Signer;
use crate::auth::signers::SignerVerification;
use crate::error::Error;
use soroban_sdk::{auth::Context, contracttype, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
}

impl SignerVerification for Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            Signer::Ed25519(signer, _) => signer.verify(env, payload, proof),
        }
    }
}

impl PermissionsCheck for Signer {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool {
        self.role().is_authorized(env, context)
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
        }
    }
}

impl Signer {
    pub fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
        }
    }
}
