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

#[test]
fn test_secp256r1_signer_creation() {
    let env = Env::default();
    let key_id = Bytes::from_array(&env, b"test_key_id");
    let public_key_bytes = [0u8; 65];
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    let signer = Secp256r1Signer::new(key_id.clone(), public_key.clone());
    assert_eq!(signer.key_id, key_id);
    assert_eq!(signer.public_key, public_key);
}

#[test]
fn test_secp256r1_signer_key_conversion() {
    let env = Env::default();
    let key_id = Bytes::from_array(&env, b"test_key_id");
    let public_key_bytes = [0u8; 65];
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    let signer = Secp256r1Signer::new(key_id.clone(), public_key);
    let signer_key: SignerKey = signer.into();

    match signer_key {
        SignerKey::Secp256r1(key) => assert_eq!(key, key_id),
        _ => panic!("Expected Secp256r1 signer key"),
    }
}

#[test]
fn test_basic_secp256r1_verification() {
    // For now, let's create a test that just validates the WebAuthn signer can be created
    // and that the signature verification logic doesn't crash on the format validation
    let env = Env::default();

    // Create a secp256r1 signer with a valid public key format
    let key_id = Bytes::from_array(&env, b"test_credential_id");
    // Valid secp256r1 public key (uncompressed format: 0x04 + 32 bytes x + 32 bytes y)
    let valid_public_key = [
        0x04, 0x8d, 0x61, 0x7e, 0x65, 0xc9, 0x50, 0x8e, 0x64, 0xbc, 0xc5, 0x67, 0x3a, 0xc8, 0x2a,
        0x67, 0x99, 0xda, 0x3c, 0x14, 0x46, 0x68, 0x2c, 0x25, 0x8c, 0x46, 0x3f, 0xff, 0xdf, 0x58,
        0xdf, 0xd2, 0xfa, 0x3e, 0x6c, 0x37, 0x8b, 0x53, 0xd7, 0x95, 0xc4, 0xa4, 0xdf, 0xfb, 0x41,
        0x99, 0xed, 0xd7, 0x86, 0x2f, 0x23, 0xab, 0xaf, 0x02, 0x03, 0xb4, 0xb8, 0x91, 0x1b, 0xa0,
        0x56, 0x99, 0x94, 0xe1, 0x01,
    ];
    let public_key = BytesN::from_array(&env, &valid_public_key);
    let signer = Secp256r1Signer::new(key_id, public_key);

    let challenge = b"test_challenge";
    let challenge_hash = env.crypto().sha256(&Bytes::from_slice(&env, challenge));
    let challenge_b64 = base64_url::encode(&challenge_hash.to_array());

    let client_data_str = std::format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64
    );
    let client_data_json = Bytes::from_slice(&env, client_data_str.as_bytes());

    let mut authenticator_data_bytes = [0u8; 37];
    authenticator_data_bytes[32] = 0x01; // User present flag
    let authenticator_data = Bytes::from_slice(&env, &authenticator_data_bytes);

    // Create a dummy signature (this will fail verification)
    let dummy_signature = BytesN::from_array(&env, &[0u8; 64]);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature: dummy_signature,
    };

    let proof = SignerProof::Secp256r1(secp256r1_sig);
    let challenge_bytes = BytesN::from_array(&env, &challenge_hash.to_array());

    // This should fail at signature verification, but not before
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        signer.verify(&env, &challenge_bytes, &proof)
    }));

    match result {
        Ok(Ok(())) => panic!("Dummy signature should not pass verification"),
        Ok(Err(_)) => panic!("Should have panicked at crypto verification, not returned error"),
        Err(_) => {}
    }
}

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
        Err(Error::ClientDataJsonChallengeIncorrect)
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
