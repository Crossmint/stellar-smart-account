use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::MlDsa65Signer;
use soroban_sdk::{crypto::Hash, Bytes, Env};

impl SignatureVerifier for MlDsa65Signer {
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::MlDsa65(signature) => {
                // Pure ML-DSA over the 32-byte payload, empty context.
                // Panics if the signature is invalid.
                env.crypto().ml_dsa_65_verify(
                    &self.public_key,
                    &Bytes::from(payload.to_bytes()),
                    signature,
                    &Bytes::new(env),
                );
                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}
