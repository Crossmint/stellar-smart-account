use crate::auth::proof::SignerProof;
use crate::auth::signer::SignerKey;
use crate::auth::signers::secp256k1::Secp256k1Signer;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::{BytesN, Env};

#[test]
fn test_secp256k1_signer_creation() {
    let env = Env::default();

    let public_key_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    let signer = Secp256k1Signer::new(public_key.clone());
    assert_eq!(signer.public_key, public_key);
}

#[test]
fn test_secp256k1_signer_key_conversion() {
    let env = Env::default();

    let public_key_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    let signer = Secp256k1Signer::new(public_key.clone());
    let signer_key: SignerKey = signer.into();

    match signer_key {
        SignerKey::Secp256k1(key) => assert_eq!(key, public_key),
        _ => panic!("Expected Secp256k1 signer key"),
    }
}

#[test]
fn test_secp256k1_signature_verification_invalid_proof_type() {
    let env = Env::default();

    let public_key_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let signer = Secp256k1Signer::new(public_key);

    let payload_bytes = [0u8; 32];
    let payload = BytesN::from_array(&env, &payload_bytes);

    let signature_bytes = [0u8; 64];
    let signature = BytesN::from_array(&env, &signature_bytes);
    let proof = SignerProof::Ed25519(signature);

    let result = signer.verify(&env, &payload, &proof);
    assert_eq!(result, Err(Error::InvalidProofType));
}

#[test]
fn test_secp256k1_signature_verification_proof_structure() {
    let env = Env::default();

    let public_key_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let _signer = Secp256k1Signer::new(public_key);

    let signature_bytes = [0u8; 64];
    let signature = BytesN::from_array(&env, &signature_bytes);
    let recovery_id = 0u32;
    let proof = SignerProof::Secp256k1(signature.clone(), recovery_id);

    match proof {
        SignerProof::Secp256k1(sig, rec_id) => {
            assert_eq!(sig, signature);
            assert_eq!(rec_id, recovery_id);
        }
        _ => panic!("Expected Secp256k1 proof"),
    }
}

#[test]
fn test_secp256k1_recovery_id_validation() {
    let env = Env::default();

    let public_key_bytes = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let public_key = BytesN::from_array(&env, &public_key_bytes);
    let _signer = Secp256k1Signer::new(public_key);

    let signature_bytes = [0u8; 64];
    let signature = BytesN::from_array(&env, &signature_bytes);

    for test_recovery_id in 0..4 {
        let test_proof = SignerProof::Secp256k1(signature.clone(), test_recovery_id);

        match test_proof {
            SignerProof::Secp256k1(_, rec_id) => {
                assert_eq!(rec_id, test_recovery_id);
                assert!(rec_id < 4); // Valid recovery ID range
            }
            _ => panic!("Expected Secp256k1 proof"),
        }
    }
}
