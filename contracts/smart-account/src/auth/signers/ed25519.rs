use crate::auth::proof::SignerProof;
use crate::auth::signer::SignerKey;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::{contracttype, symbol_short, Bytes, BytesN, Env};

/// Ed25519 signer implementation
#[contracttype]
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

impl SignatureVerifier for Ed25519Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Ed25519(signature) => {
                env.crypto().ed25519_verify(
                    &self.public_key,
                    &Bytes::from(payload.clone()),
                    signature,
                );
                Ok(())
            }
            SignerProof::Secp256r1(_) => {
                env.events().publish(
                    (symbol_short!("sig"), symbol_short!("failed")),
                    crate::account::SignatureVerificationFailedEvent {
                        error_code: 7,
                        error_message: soroban_sdk::String::from_str(env, "InvalidProofType"),
                        signer_key: soroban_sdk::String::from_str(env, "ed25519_key"),
                        proof_type: soroban_sdk::String::from_str(env, "secp256r1_mismatch"),
                    },
                );
                Err(Error::InvalidProofType)
            }
        }
    }
}

impl From<Ed25519Signer> for SignerKey {
    fn from(signer: Ed25519Signer) -> Self {
        SignerKey::Ed25519(signer.public_key.clone())
    }
}
