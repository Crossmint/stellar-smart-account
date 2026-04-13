use crate::auth::proof::{SignerProof, WebauthnSignature};
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use base64ct::{Base64UrlUnpadded, Encoding};
use smart_account_interfaces::WebauthnSigner;
use soroban_sdk::{crypto::Hash, Env};

#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    challenge: &'a str,
}

impl SignatureVerifier for WebauthnSigner {
    fn verify(
        &self,
        env: &Env,
        signature_payload: &Hash<32>,
        proof: &SignerProof,
    ) -> Result<(), Error> {
        match proof {
            SignerProof::Webauthn(signature) => {
                let WebauthnSignature {
                    mut authenticator_data,
                    client_data_json,
                    signature,
                } = signature.clone();

                // Cheap checks first — reject malformed inputs before expensive crypto

                // WebAuthn authenticator data: rpIdHash (32) + flags (1) + signCount (4) = 37 min
                if authenticator_data.len() < 37 {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

                if client_data_json.len() > 1024 {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

                let client_data_json_buf = client_data_json.to_buffer::<1024>();
                let (parsed_client_data, _): (ClientDataJson, _) =
                    serde_json_core::de::from_slice(client_data_json_buf.as_slice())
                        .map_err(|_| Error::InvalidWebauthnClientDataJson)?;

                let mut buf = [0u8; 64];
                let expected_challenge =
                    Base64UrlUnpadded::encode(&signature_payload.to_bytes().to_array(), &mut buf)
                        .map_err(|_| Error::InvalidWebauthnClientDataJson)?;
                if parsed_client_data.challenge.as_bytes() != expected_challenge.as_bytes() {
                    return Err(Error::ClientDataJsonIncorrectChallenge);
                }

                // Expensive crypto — only reached for structurally valid inputs
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
