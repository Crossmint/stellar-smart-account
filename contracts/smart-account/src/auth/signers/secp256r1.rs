use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::Secp256r1Signer;
use soroban_sdk::{BytesN, Env};

impl SignatureVerifier for Secp256r1Signer {
    fn verify(
        &self,
        env: &Env,
        signature_payload: &BytesN<32>,
        proof: &SignerProof,
    ) -> Result<(), Error> {
        match proof {
            SignerProof::Secp256r1(signature) => {
                // This will panic if the signature is invalid.
                // Uses crypto_hazmat to accept BytesN<32> directly (the signature_payload
                // is already a hash from __check_auth).
                env.crypto_hazmat().secp256r1_verify(
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
