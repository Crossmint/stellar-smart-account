// External crates
extern crate alloc;
extern crate std;

// Standard library imports
use alloc::vec::Vec;

// Third-party crate imports
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Signer as P256Signer, Signature, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use soroban_sdk::{map, vec, Address, Bytes, BytesN, Env, IntoVal, Vec as SorobanVec};

// Internal crate imports
use crate::account::SmartAccount;
use crate::auth::permissions::SignerRole;
use crate::auth::proof::{Secp256r1Signature, SignatureProofs, SignerProof};
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::secp256r1::Secp256r1Signer;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use crate::tests::test_utils::get_token_auth_context;

// Helper functions for WebAuthn testing
mod webauthn_helpers {
    use super::*;

    #[derive(Serialize)]
    pub struct ClientData<'a> {
        #[serde(rename = "type")]
        pub ty: &'a str,
        pub challenge: &'a str,
        pub origin: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "crossOrigin")]
        pub cross_origin: Option<bool>,
    }

    pub struct WebAuthnTestData {
        pub signer: Secp256r1Signer,
        pub signature_payload: BytesN<32>,
        pub valid_proof: SignerProof,
        pub signing_key: SigningKey,
    }

    pub fn create_webauthn_test_data(env: &Env) -> WebAuthnTestData {
        // Create deterministic keypair
        let sk_bytes = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_bytes.into()).expect("signing key");
        let verifying_key = VerifyingKey::from(&signing_key);

        // Convert to Soroban format
        let public_key_encoded = verifying_key.to_encoded_point(false);
        let mut pk_bytes = [0u8; 65];
        pk_bytes.copy_from_slice(public_key_encoded.as_bytes());

        let key_id = Bytes::from_array(env, b"test_credential_id");
        let signer = Secp256r1Signer::new(key_id, BytesN::from_array(env, &pk_bytes));

        // Create challenge
        let signature_payload = BytesN::from_array(env, &[0xAB; 32]);
        let challenge_b64 = Base64UrlUnpadded::encode_string(&signature_payload.to_array());

        // Create client data JSON
        let client_data = ClientData {
            ty: "webauthn.get",
            challenge: &challenge_b64,
            origin: "https://example.com",
            cross_origin: None,
        };
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        // Create authenticator data (RP hash + flags + counter)
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"example.com"));
        authenticator_data.push(0x01); // User present flag
        authenticator_data.extend_from_slice(&42u32.to_be_bytes()); // Counter

        // Create signature
        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let signature: Signature = signing_key.sign(&signed_data);

        // Create valid proof
        let valid_proof = SignerProof::Secp256r1(Secp256r1Signature {
            authenticator_data: Bytes::from_slice(env, &authenticator_data),
            client_data_json: Bytes::from_slice(env, &client_data_json),
            signature: BytesN::from_array(env, signature.to_bytes().as_slice().try_into().unwrap()),
        });

        WebAuthnTestData {
            signer,
            signature_payload,
            valid_proof,
            signing_key,
        }
    }

    pub fn create_wrong_challenge_proof(env: &Env, test_data: &WebAuthnTestData) -> SignerProof {
        let correct_challenge =
            Base64UrlUnpadded::encode_string(&test_data.signature_payload.to_array());
        let wrong_challenge =
            std::format!("{}X", &correct_challenge[..correct_challenge.len() - 1]);

        let client_data = ClientData {
            ty: "webauthn.get",
            challenge: &wrong_challenge,
            origin: "https://example.com",
            cross_origin: None,
        };
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        // Create authenticator data and signature (same as valid case)
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"example.com"));
        authenticator_data.push(0x01);
        authenticator_data.extend_from_slice(&42u32.to_be_bytes());

        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let signature: Signature = test_data.signing_key.sign(&signed_data);

        SignerProof::Secp256r1(Secp256r1Signature {
            authenticator_data: Bytes::from_slice(env, &authenticator_data),
            client_data_json: Bytes::from_slice(env, &client_data_json),
            signature: BytesN::from_array(env, signature.to_bytes().as_slice().try_into().unwrap()),
        })
    }

    pub fn create_invalid_signature_proof(env: &Env, test_data: &WebAuthnTestData) -> SignerProof {
        if let SignerProof::Secp256r1(ref valid_sig) = test_data.valid_proof {
            let mut bad_sig_bytes = valid_sig.signature.to_array().to_vec();
            bad_sig_bytes[0] ^= 0x01; // Corrupt the signature

            SignerProof::Secp256r1(Secp256r1Signature {
                authenticator_data: valid_sig.authenticator_data.clone(),
                client_data_json: valid_sig.client_data_json.clone(),
                signature: BytesN::from_array(env, bad_sig_bytes.as_slice().try_into().unwrap()),
            })
        } else {
            panic!("Expected Secp256r1 proof");
        }
    }
}

#[test]
fn test_secp256r1_webauthn_valid_signature_passes() {
    let env = Env::default();
    let test_data = webauthn_helpers::create_webauthn_test_data(&env);

    // Should pass completely - all WebAuthn validation steps
    test_data
        .signer
        .verify(&env, &test_data.signature_payload, &test_data.valid_proof)
        .unwrap();
}

#[test]
fn test_secp256r1_webauthn_wrong_challenge_rejected() {
    let env = Env::default();
    let test_data = webauthn_helpers::create_webauthn_test_data(&env);
    let wrong_proof = webauthn_helpers::create_wrong_challenge_proof(&env, &test_data);

    let result = test_data
        .signer
        .verify(&env, &test_data.signature_payload, &wrong_proof);
    assert!(matches!(
        result,
        Err(Error::ClientDataJsonIncorrectChallenge)
    ));
}

#[test]
#[should_panic]
fn test_secp256r1_webauthn_invalid_signature_panics() {
    let env = Env::default();
    let test_data = webauthn_helpers::create_webauthn_test_data(&env);
    let invalid_proof = webauthn_helpers::create_invalid_signature_proof(&env, &test_data);

    // Should panic at crypto verification step
    let _ = test_data
        .signer
        .verify(&env, &test_data.signature_payload, &invalid_proof);
}

#[test]
fn test_secp256r1_end_to_end_smart_account_auth() {
    let env = Env::default();

    // Use the same approach as the working webauthn_helpers
    let test_data = webauthn_helpers::create_webauthn_test_data(&env);

    // Register smart account with the secp256r1 signer from test_data
    let signer = Signer::Secp256r1(test_data.signer.clone(), SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, signer], SorobanVec::<Address>::new(&env)),
    );

    // Use the same payload and proof from test_data
    let signer_key = SignerKey::Secp256r1(test_data.signer.key_id.clone());
    let auth_payloads = SignatureProofs(map![&env, (signer_key, test_data.valid_proof)]);

    // Test end-to-end authentication
    let result = env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &test_data.signature_payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    match result {
        Ok(()) => {
            // Success - test passed
        }
        Err(e) => {
            panic!("Authentication failed: {:?}", e);
        }
    }
}
