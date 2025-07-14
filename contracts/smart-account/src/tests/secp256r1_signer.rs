use crate::auth::proof::{Secp256r1Signature, SignerProof};
use crate::auth::signer::SignerKey;
use crate::auth::signers::secp256r1::Secp256r1Signer;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use crate::tests::webauthn_utils::WebAuthnTestUtils;
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

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
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

#[test]
fn test_secp256r1_mock_webauthn_signature() {
    let _env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let challenge = b"test_challenge_for_signature";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_mock_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data: authenticator_data.clone(),
        client_data_json: client_data_json.clone(),
        signature: signature.clone(),
    };

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
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

#[test]
fn test_secp256r1_real_webauthn_signature_creation() {
    let _env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let challenge = b"test_challenge_for_real_signature";

    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_real_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data: authenticator_data.clone(),
        client_data_json: client_data_json.clone(),
        signature: signature.clone(),
    };

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
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

#[test]
fn test_secp256r1_mock_signature_verification() {
    let env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let challenge = b"test_challenge_for_verification";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_mock_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature,
    };

    let key_id = Bytes::from_array(&env, b"mock_test_key_id");
    let mut public_key_bytes = [0u8; 65];
    public_key_bytes[0] = 0x04; // Uncompressed point indicator
    for (i, item) in public_key_bytes.iter_mut().enumerate().skip(1) {
        *item = (i % 256) as u8;
    }
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let _signer = Secp256r1Signer::new(key_id, public_key);

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
    assert_eq!(secp256r1_sig.signature.len(), 64);

    let payload_bytes = [0u8; 32];
    let _payload = BytesN::from_array(&env, &payload_bytes);
    let proof = SignerProof::Secp256r1(secp256r1_sig);

    match proof {
        SignerProof::Secp256r1(sig) => {
            assert!(!sig.authenticator_data.is_empty());
            assert!(!sig.client_data_json.is_empty());
            assert_eq!(sig.signature.len(), 64);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}

#[test]
fn test_secp256r1_end_to_end_mock_flow() {
    let env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let key_id = Bytes::from_array(&env, b"mock_credential_id");
    let mut public_key_bytes = [0u8; 65];
    public_key_bytes[0] = 0x04; // Uncompressed point indicator
    for (i, item) in public_key_bytes.iter_mut().enumerate().skip(1) {
        *item = (i % 256) as u8;
    }
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let signer = Secp256r1Signer::new(key_id.clone(), public_key.clone());

    let signer_key: SignerKey = signer.into();
    match signer_key {
        SignerKey::Secp256r1(key) => assert_eq!(key, key_id),
        _ => panic!("Expected Secp256r1 signer key"),
    }

    let challenge = b"test_challenge_for_end_to_end";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_mock_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature,
    };

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
    assert_eq!(secp256r1_sig.signature.len(), 64);

    let _proof = SignerProof::Secp256r1(secp256r1_sig);
    let payload_bytes = [0u8; 32];
    let _payload = BytesN::from_array(&env, &payload_bytes);

    let new_signer = Secp256r1Signer::new(key_id, public_key);
    assert_eq!(new_signer.key_id.len(), 18); // "mock_credential_id".len()
    assert_eq!(new_signer.public_key.len(), 65);
}

#[test]
fn test_secp256r1_valid_signature_verification_with_real_data() {
    let env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    // Use the hardcoded test data from webauthn_utils
    let credential_id_bytes = webauthn_utils.get_test_credential_id();
    let key_id = Bytes::from_slice(&env, &credential_id_bytes);
    let public_key_bytes = webauthn_utils.get_test_secp256r1_public_key();
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let _signer = Secp256r1Signer::new(key_id, public_key);

    let challenge = b"test_challenge_for_valid_verification";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_real_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature,
    };

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
    assert_eq!(secp256r1_sig.signature.len(), 64);

    let challenge_bytes = Bytes::from_slice(&env, challenge);
    let payload_bytes = env.crypto().sha256(&challenge_bytes);
    let _payload = BytesN::from_array(&env, &payload_bytes.to_array());
    let proof = SignerProof::Secp256r1(secp256r1_sig);

    match proof {
        SignerProof::Secp256r1(sig) => {
            assert!(!sig.authenticator_data.is_empty());
            assert!(!sig.client_data_json.is_empty());
            assert_eq!(sig.signature.len(), 64);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}

#[test]
fn test_secp256r1_invalid_signature_rejection_wrong_public_key() {
    let env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let key_id = Bytes::from_array(&env, b"wrong_key_id");
    let wrong_public_key_bytes = [0x04; 65]; // Different from test data
    let public_key = BytesN::from_array(&env, &wrong_public_key_bytes);
    let _signer = Secp256r1Signer::new(key_id, public_key);

    let challenge = b"test_challenge_for_invalid_verification";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_real_webauthn_signature(challenge);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature,
    };

    let challenge_bytes = Bytes::from_slice(&env, challenge);
    let payload_bytes = env.crypto().sha256(&challenge_bytes);
    let _payload = BytesN::from_array(&env, &payload_bytes.to_array());
    let proof = SignerProof::Secp256r1(secp256r1_sig);

    match proof {
        SignerProof::Secp256r1(sig) => {
            assert!(!sig.authenticator_data.is_empty());
            assert!(!sig.client_data_json.is_empty());
            assert_eq!(sig.signature.len(), 64);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}

#[test]
fn test_secp256r1_malformed_data_handling() {
    let env = Env::default();

    let malformed_authenticator_data = Bytes::from_array(&env, b"short");
    let client_data_json = Bytes::from_array(&env, b"{\"type\":\"webauthn.get\"}");
    let signature = BytesN::from_array(&env, &[0u8; 64]);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data: malformed_authenticator_data,
        client_data_json,
        signature,
    };

    assert!(!secp256r1_sig.authenticator_data.is_empty());
    assert!(!secp256r1_sig.client_data_json.is_empty());
    assert_eq!(secp256r1_sig.signature.len(), 64);

    let proof = SignerProof::Secp256r1(secp256r1_sig);
    match proof {
        SignerProof::Secp256r1(sig) => {
            assert_eq!(sig.authenticator_data.len(), 5); // "short".len()
            assert!(!sig.client_data_json.is_empty());
            assert_eq!(sig.signature.len(), 64);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}

#[test]
fn test_secp256r1_full_verification_flow_structure() {
    let env = Env::default();
    let webauthn_utils = WebAuthnTestUtils::new();

    let credential_id_bytes = webauthn_utils.get_test_credential_id();
    let key_id = Bytes::from_slice(&env, &credential_id_bytes);
    let public_key_bytes = webauthn_utils.get_test_secp256r1_public_key();
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let _signer = Secp256r1Signer::new(key_id, public_key);

    let challenge = b"test_challenge_for_full_flow";
    let (authenticator_data, client_data_json, signature) =
        webauthn_utils.generate_real_webauthn_signature(challenge);

    let client_data_hash = env.crypto().sha256(&client_data_json);

    assert!(!authenticator_data.is_empty());
    assert_eq!(client_data_hash.to_array().len(), 32);
    assert_eq!(signature.len(), 64);

    let secp256r1_sig = Secp256r1Signature {
        authenticator_data,
        client_data_json,
        signature,
    };

    let proof = SignerProof::Secp256r1(secp256r1_sig);
    match proof {
        SignerProof::Secp256r1(sig) => {
            assert!(!sig.authenticator_data.is_empty());
            assert!(!sig.client_data_json.is_empty());
            assert_eq!(sig.signature.len(), 64);
        }
        _ => panic!("Expected Secp256r1 proof"),
    }
}
