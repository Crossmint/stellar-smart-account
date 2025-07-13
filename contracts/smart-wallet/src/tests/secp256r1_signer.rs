use crate::auth::proof::{Secp256r1Signature, SignerProof};
use crate::auth::signer::SignerKey;
use crate::auth::signers::secp256r1::Secp256r1Signer;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::{Bytes, BytesN, Env};

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
fn test_secp256r1_signature_structure() {
    let env = Env::default();
    let authenticator_data = Bytes::from_array(&env, b"authenticator_data");
    let client_data_json = Bytes::from_array(&env, b"client_data_json");
    let signature = BytesN::from_array(&env, &[0u8; 64]);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data: authenticator_data.clone(),
        client_data_json: client_data_json.clone(),
        signature: signature.clone(),
    };

    assert_eq!(secp256r1_sig.authenticator_data, authenticator_data);
    assert_eq!(secp256r1_sig.client_data_json, client_data_json);
    assert_eq!(secp256r1_sig.signature, signature);

    let proof = SignerProof::Secp256r1(secp256r1_sig);
    match proof {
        SignerProof::Secp256r1(sig) => {
            assert_eq!(sig.authenticator_data, authenticator_data);
            assert_eq!(sig.client_data_json, client_data_json);
            assert_eq!(sig.signature, signature);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}

#[test]
fn test_secp256r1_signature_verification_invalid_proof_type() {
    let env = Env::default();
    let key_id = Bytes::from_array(&env, b"test_key_id");
    let public_key_bytes = [0u8; 65];
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let signer = Secp256r1Signer::new(key_id, public_key);

    let payload_bytes = [0u8; 32];
    let payload = BytesN::from_array(&env, &payload_bytes);

    let signature_bytes = [0u8; 64];
    let signature = BytesN::from_array(&env, &signature_bytes);
    let proof = SignerProof::Ed25519(signature);

    let result = signer.verify(&env, &payload, &proof);
    assert_eq!(result, Err(Error::InvalidProofType));
}

#[test]
fn test_secp256r1_webauthn_components() {
    let env = Env::default();

    let authenticator_data = Bytes::from_array(&env, b"mock_authenticator_data");
    let client_data_json =
        Bytes::from_array(&env, b"{\"type\":\"webauthn.get\",\"challenge\":\"test\"}");
    let signature = BytesN::from_array(&env, &[1u8; 64]);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data: authenticator_data.clone(),
        client_data_json: client_data_json.clone(),
        signature: signature.clone(),
    };

    assert!(secp256r1_sig.authenticator_data.len() > 0);
    assert!(secp256r1_sig.client_data_json.len() > 0);
    assert_eq!(secp256r1_sig.signature.len(), 64);

    let proof = SignerProof::Secp256r1(secp256r1_sig);
    match proof {
        SignerProof::Secp256r1(sig) => {
            assert_eq!(sig.authenticator_data, authenticator_data);
            assert_eq!(sig.client_data_json, client_data_json);
            assert_eq!(sig.signature, signature);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}
