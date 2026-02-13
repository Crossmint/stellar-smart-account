// Third-party crate imports
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use soroban_sdk::{map, vec, Address, BytesN, Env, IntoVal, Vec as SorobanVec};

// Internal crate imports
use crate::account::SmartAccount;
use crate::auth::proof::{SignatureProofs, SignerProof};
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use crate::tests::test_utils::get_token_auth_context;
use smart_account_interfaces::SignerRole;
use smart_account_interfaces::{Secp256r1Signer, Signer, SignerKey};

struct Secp256r1TestData {
    signer: Secp256r1Signer,
    signature_payload: BytesN<32>,
    valid_proof: SignerProof,
}

fn create_secp256r1_test_data(env: &Env) -> Secp256r1TestData {
    // Create deterministic keypair
    let sk_bytes = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&sk_bytes.into()).expect("signing key");
    let verifying_key = VerifyingKey::from(&signing_key);

    // Convert to Soroban format
    let public_key_encoded = verifying_key.to_encoded_point(false);
    let mut pk_bytes = [0u8; 65];
    pk_bytes.copy_from_slice(public_key_encoded.as_bytes());

    let signer = Secp256r1Signer::new(BytesN::from_array(env, &pk_bytes));

    // Create payload
    let signature_payload = BytesN::from_array(env, &[0xAB; 32]);

    // Sign the payload as a pre-hashed message (no additional hashing).
    // Soroban's secp256r1_verify treats the 32-byte input as a message digest directly.
    let signature: Signature = signing_key
        .sign_prehash(&signature_payload.to_array())
        .expect("signing");

    let valid_proof = SignerProof::Secp256r1(BytesN::from_array(
        env,
        signature.to_bytes().as_slice().try_into().unwrap(),
    ));

    Secp256r1TestData {
        signer,
        signature_payload,
        valid_proof,
    }
}

#[test]
fn test_secp256r1_raw_valid_signature_passes() {
    let env = Env::default();
    let test_data = create_secp256r1_test_data(&env);

    test_data
        .signer
        .verify(&env, &test_data.signature_payload, &test_data.valid_proof)
        .unwrap();
}

#[test]
#[should_panic]
fn test_secp256r1_raw_invalid_signature_panics() {
    let env = Env::default();
    let test_data = create_secp256r1_test_data(&env);

    if let SignerProof::Secp256r1(ref valid_sig) = test_data.valid_proof {
        let mut bad_sig_bytes = valid_sig.to_array().to_vec();
        bad_sig_bytes[0] ^= 0x01; // Corrupt the signature

        let invalid_proof = SignerProof::Secp256r1(BytesN::from_array(
            &env,
            bad_sig_bytes.as_slice().try_into().unwrap(),
        ));

        // Should panic at crypto verification step
        let _ = test_data
            .signer
            .verify(&env, &test_data.signature_payload, &invalid_proof);
    } else {
        panic!("Expected Secp256r1 proof");
    }
}

#[test]
fn test_secp256r1_raw_wrong_proof_type_rejected() {
    let env = Env::default();
    let test_data = create_secp256r1_test_data(&env);

    // Try with an Ed25519 proof type
    let wrong_proof = SignerProof::Ed25519(BytesN::from_array(&env, &[0u8; 64]));
    let result = test_data
        .signer
        .verify(&env, &test_data.signature_payload, &wrong_proof);
    assert!(matches!(result, Err(Error::InvalidProofType)));
}

#[test]
fn test_secp256r1_raw_end_to_end_smart_account_auth() {
    let env = Env::default();
    let test_data = create_secp256r1_test_data(&env);

    // Register smart account with the secp256r1 signer
    let signer = Signer::Secp256r1(test_data.signer.clone(), SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, signer], SorobanVec::<Address>::new(&env)),
    );

    // Use the same payload and proof
    let signer_key = SignerKey::Secp256r1(test_data.signer.public_key.clone());
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
