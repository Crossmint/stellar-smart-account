use crate::auth::proof::{Secp256r1Signature, SignerProof};
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use base64ct::{Base64UrlUnpadded, Encoding};
use smart_account_interfaces::Secp256r1Signer;
use smart_account_interfaces::SignerKey;
use soroban_sdk::{Bytes, BytesN, Env};

#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    challenge: &'a str,
}

impl SignatureVerifier for Secp256r1Signer {
    fn verify(
        &self,
        env: &Env,
        signature_payload: &BytesN<32>,
        proof: &SignerProof,
    ) -> Result<(), Error> {
        match proof {
            SignerProof::Secp256r1(signature) => {
                let Secp256r1Signature {
                    mut authenticator_data,
                    client_data_json,
                    signature,
                } = signature.clone();

                authenticator_data
                    .extend_from_array(&env.crypto().sha256(&client_data_json).to_array());

                // This will panic if the signature is invalid
                env.crypto().secp256r1_verify(
                    &self.public_key,
                    &env.crypto().sha256(&authenticator_data),
                    &signature,
                );

                if client_data_json.len() > 1024 {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

                let client_data_json = client_data_json.to_buffer::<1024>();
                let client_data_json = client_data_json.as_slice();
                let (client_data_json, _): (ClientDataJson, _) =
                    serde_json_core::de::from_slice(client_data_json)
                        .map_err(|_| Error::InvalidWebauthnClientDataJson)?;

                let mut buf = [0u8; 64];
                let expected_challenge =
                    Base64UrlUnpadded::encode(&signature_payload.to_array(), &mut buf)
                        .map_err(|_| Error::InvalidWebauthnClientDataJson)?;
                if client_data_json.challenge.as_bytes() != expected_challenge.as_bytes() {
                    return Err(Error::ClientDataJsonIncorrectChallenge);
                }

                // // Reaching this point means the signature is valid
                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

// From<Secp256r1Signer> for SignerKey implemented in interfaces crate
