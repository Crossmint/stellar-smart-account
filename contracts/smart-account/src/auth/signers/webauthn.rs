use crate::auth::proof::{SignerProof, WebauthnSignature};
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use base64ct::{Base64UrlUnpadded, Encoding};
use smart_account_interfaces::WebauthnSigner;
use soroban_sdk::{crypto::Hash, Env};

/// WebAuthn assertion `clientDataJSON` fields the verifier inspects.
///
/// Per W3C WebAuthn §7.2.11, an authentication assertion MUST set
/// `type` to `"webauthn.get"`. We pin both `type` and `challenge`; other
/// fields (`origin`, `crossOrigin`) are intentionally ignored here —
/// `origin` enforcement requires per-signer expected-origin storage and
/// is tracked for a future schema change.
#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    #[serde(rename = "type")]
    ty: &'a str,
    challenge: &'a str,
}

const WEBAUTHN_GET_TYPE: &str = "webauthn.get";

/// Authenticator-data flag bits (WebAuthn §6.1).
const FLAG_USER_PRESENT: u8 = 0x01;

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

                // The User-Present (UP) bit MUST be set for a valid assertion.
                // `authenticator_data[32]` is the flags byte.
                let flags = authenticator_data.get(32).unwrap_or(0);
                if flags & FLAG_USER_PRESENT == 0 {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

                if client_data_json.len() > 1024 {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

                let client_data_json_buf = client_data_json.to_buffer::<1024>();
                let (parsed_client_data, _): (ClientDataJson, _) =
                    serde_json_core::de::from_slice(client_data_json_buf.as_slice())
                        .map_err(|_| Error::InvalidWebauthnClientDataJson)?;

                // Reject anything that isn't a WebAuthn authentication ceremony
                // — this prevents a webauthn.create signature from being replayed
                // as a webauthn.get assertion.
                if parsed_client_data.ty != WEBAUTHN_GET_TYPE {
                    return Err(Error::InvalidWebauthnClientDataJson);
                }

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
