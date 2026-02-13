use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::Ed25519Signer;
use soroban_sdk::{crypto::Hash, Bytes, Env};

impl SignatureVerifier for Ed25519Signer {
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Ed25519(signature) => {
                // This will panic if the signature is invalid
                env.crypto().ed25519_verify(
                    &self.public_key,
                    &Bytes::from(payload.to_bytes()),
                    signature,
                );
                // Reaching this point means the signature is valid
                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

// From<Ed25519Signer> for SignerKey implemented in interfaces crate
