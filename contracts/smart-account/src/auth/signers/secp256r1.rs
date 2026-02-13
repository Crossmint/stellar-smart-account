use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::Secp256r1Signer;
use soroban_sdk::{crypto::Hash, Env};

impl SignatureVerifier for Secp256r1Signer {
    fn verify(
        &self,
        env: &Env,
        signature_payload: &Hash<32>,
        proof: &SignerProof,
    ) -> Result<(), Error> {
        match proof {
            SignerProof::Secp256r1(signature) => {
                // This will panic if the signature is invalid.
                // The signature_payload is a Hash<32> from __check_auth,
                // guaranteed to be a secure cryptographic hash.
                env.crypto().secp256r1_verify(
                    &self.public_key,
                    signature_payload,
                    signature,
                );

                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}
