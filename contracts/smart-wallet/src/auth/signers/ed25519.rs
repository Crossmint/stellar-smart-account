use super::SignerVerification;
use crate::auth::signature::SignerProof;
use crate::auth::signer::SignerKey;
use crate::error::Error;
use soroban_sdk::{contracttype, Bytes, BytesN, Env};

/// Ed25519 signer implementation
#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer with the given public key
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

impl SignerVerification for Ed25519Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Ed25519(signature) => {
                env.crypto().ed25519_verify(
                    &self.public_key,
                    &Bytes::from(payload.clone()),
                    &signature.clone(),
                );
                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

impl From<Ed25519Signer> for SignerKey {
    fn from(signer: Ed25519Signer) -> Self {
        SignerKey::Ed25519(signer.public_key.clone())
    }
}
