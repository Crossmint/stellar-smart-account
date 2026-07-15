use soroban_sdk::{map, testutils::BytesN as _, vec, Address, Bytes, BytesN, IntoVal, Vec};

use crate::{
    account::SmartAccount,
    auth::proof::{SignatureProofs, SignerProof},
    auth::signers::SignatureVerifier,
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, TestSignerTrait as _, WebauthnTestSigner},
};
use smart_account_interfaces::SignerRole;

#[test]
fn test_webauthn_valid_signature() {
    let env = setup();
    let signer = WebauthnTestSigner::generate(SignerRole::Admin);

    // Produce a Hash<32> the same way __check_auth receives it
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, proof) = signer.sign(&env, &payload_hash.to_bytes());

    signer
        .into_signer(&env)
        .verify(&env, &payload_hash, &proof)
        .unwrap();
}

#[test]
fn test_webauthn_wrong_challenge_rejected() {
    let env = setup();
    let signer = WebauthnTestSigner::generate(SignerRole::Admin);

    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, wrong_proof) = signer.sign_wrong_challenge(&env, &payload_hash.to_bytes());

    let result = signer
        .into_signer(&env)
        .verify(&env, &payload_hash, &wrong_proof);
    assert!(matches!(
        result,
        Err(Error::ClientDataJsonIncorrectChallenge)
    ));
}

#[test]
#[should_panic]
fn test_webauthn_invalid_signature_panics() {
    let env = setup();
    let signer = WebauthnTestSigner::generate(SignerRole::Admin);

    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, valid_proof) = signer.sign(&env, &payload_hash.to_bytes());

    // Corrupt the signature bytes
    let invalid_proof = if let SignerProof::Webauthn(ref sig) = valid_proof {
        let mut bad_bytes = sig.signature.to_array().to_vec();
        bad_bytes[0] ^= 0x01;
        SignerProof::Webauthn(crate::auth::proof::WebauthnSignature {
            authenticator_data: sig.authenticator_data.clone(),
            client_data_json: sig.client_data_json.clone(),
            signature: BytesN::from_array(&env, bad_bytes.as_slice().try_into().unwrap()),
        })
    } else {
        panic!("Expected Webauthn proof");
    };

    let _ = signer
        .into_signer(&env)
        .verify(&env, &payload_hash, &invalid_proof);
}

#[test]
fn test_webauthn_end_to_end_auth() {
    let env = setup();
    let test_signer = WebauthnTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// Spec compliance: WebAuthn assertions must use type "webauthn.get" (W3C §7.2.11)
// ============================================================================

#[test]
fn test_webauthn_wrong_type_rejected() {
    let env = setup();
    let signer = WebauthnTestSigner::generate(SignerRole::Admin);

    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, wrong_type_proof) = signer.sign_with_wrong_type(&env, &payload_hash.to_bytes());

    let result = signer
        .into_signer(&env)
        .verify(&env, &payload_hash, &wrong_type_proof);
    assert!(matches!(
        result,
        Err(Error::InvalidWebauthnClientDataJson)
    ));
}

#[test]
fn test_webauthn_wrong_type_rejected_end_to_end() {
    let env = setup();
    let test_signer = WebauthnTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign_with_wrong_type(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Ok(err) => assert_eq!(err, Error::InvalidWebauthnClientDataJson),
        Err(other) => panic!("unexpected host error {:?}", other),
    }
}

// ============================================================================
// Spec compliance: User-Present (UP) flag must be set (W3C §6.1)
// ============================================================================

#[test]
fn test_webauthn_missing_user_present_flag_rejected() {
    let env = setup();
    let signer = WebauthnTestSigner::generate(SignerRole::Admin);

    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, proof) = signer.sign_without_user_present(&env, &payload_hash.to_bytes());

    let result = signer
        .into_signer(&env)
        .verify(&env, &payload_hash, &proof);
    assert!(matches!(
        result,
        Err(Error::InvalidWebauthnClientDataJson)
    ));
}
