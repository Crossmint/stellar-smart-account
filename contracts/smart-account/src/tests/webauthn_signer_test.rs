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
// key_id length bound: anything over 1023 bytes is rejected at registration
// (matches the FIDO2/CTAP2 CredentialID cap).
// ============================================================================

#[test]
fn test_webauthn_oversize_key_id_rejected() {
    use crate::account::SmartAccount;
    use smart_account_interfaces::{Signer, SmartAccountInterface as _, WebauthnSigner};
    use soroban_sdk::testutils::Address as _;

    let env = setup();
    env.mock_all_auths();

    // Deploy with a valid admin first.
    let admin = crate::tests::test_utils::WebauthnTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Build a Webauthn signer whose key_id is 1024 bytes — over the cap.
    let oversize = Bytes::from_slice(&env, &[0xAAu8; 1024]);
    let pk_bytes = [0x04u8; 65];
    let bad_signer = Signer::Webauthn(
        WebauthnSigner {
            key_id: oversize,
            public_key: BytesN::from_array(&env, &pk_bytes),
        },
        SignerRole::Standard(None, 0),
    );

    let err = env
        .as_contract(&contract_id, || {
            SmartAccount::add_signer(&env, bad_signer)
        })
        .unwrap_err();
    assert_eq!(err, Error::InvalidPolicy);
}

#[test]
fn test_webauthn_max_size_key_id_accepted() {
    use crate::account::SmartAccount;
    use smart_account_interfaces::{Signer, SmartAccountInterface as _, WebauthnSigner};

    let env = setup();
    env.mock_all_auths();

    let admin = crate::tests::test_utils::WebauthnTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Exactly 1023 bytes — the FIDO2/CTAP2 cap — must pass.
    let exact = Bytes::from_slice(&env, &[0xBBu8; 1023]);
    let pk_bytes = [0x04u8; 65];
    let ok_signer = Signer::Webauthn(
        WebauthnSigner {
            key_id: exact,
            public_key: BytesN::from_array(&env, &pk_bytes),
        },
        SignerRole::Standard(None, 0),
    );

    env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, ok_signer)
    })
    .unwrap();
}
