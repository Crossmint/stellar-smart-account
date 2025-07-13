use crate::auth::proof::{Secp256r1Signature, SignerProof};
use crate::auth::signer::SignerKey;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::{contracttype, Bytes, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

impl Secp256r1Signer {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

impl SignatureVerifier for Secp256r1Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Secp256r1(signature) => {
                let Secp256r1Signature {
                    mut authenticator_data,
                    client_data_json,
                    signature,
                } = signature.clone();

                authenticator_data
                    .extend_from_array(&env.crypto().sha256(&client_data_json).to_array());

                env.crypto().secp256r1_verify(
                    &self.public_key,
                    &env.crypto().sha256(&authenticator_data),
                    &signature,
                );

                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

impl From<Secp256r1Signer> for SignerKey {
    fn from(signer: Secp256r1Signer) -> Self {
        SignerKey::Secp256r1(signer.key_id.clone())
    }
}
