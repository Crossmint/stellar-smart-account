use soroban_sdk::{map, testutils::BytesN as _, vec, Address, Bytes, BytesN, IntoVal, Vec};

use crate::{
    account::SmartAccount,
    auth::proof::{SignatureProofs, SignerProof},
    auth::signers::SignatureVerifier,
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, Secp256r1TestSigner, TestSignerTrait as _},
};
use smart_account_interfaces::SignerRole;

#[test]
fn test_secp256r1_valid_signature() {
    let env = setup();
    let signer = Secp256r1TestSigner::generate(SignerRole::Admin);

    // Produce a Hash<32> the same way __check_auth receives it
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));
    let (_, proof) = signer.sign(&env, &payload_hash.to_bytes());

    smart_account_interfaces::Secp256r1Signer::new(signer.public_key(&env))
        .verify(&env, &payload_hash, &proof)
        .unwrap();
}

#[test]
#[should_panic]
fn test_secp256r1_invalid_signature_panics() {
    let env = setup();
    let signer = Secp256r1TestSigner::generate(SignerRole::Admin);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));

    let invalid_proof = SignerProof::Secp256r1(BytesN::random(&env));

    let _ = smart_account_interfaces::Secp256r1Signer::new(signer.public_key(&env)).verify(
        &env,
        &payload_hash,
        &invalid_proof,
    );
}

#[test]
fn test_secp256r1_wrong_proof_type_rejected() {
    let env = setup();
    let signer = Secp256r1TestSigner::generate(SignerRole::Admin);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xAB; 32]));

    let wrong_proof = SignerProof::Ed25519(BytesN::random(&env));
    let result = smart_account_interfaces::Secp256r1Signer::new(signer.public_key(&env)).verify(
        &env,
        &payload_hash,
        &wrong_proof,
    );
    assert!(matches!(result, Err(Error::InvalidProofType)));
}

#[test]
fn test_secp256r1_end_to_end_auth() {
    let env = setup();
    let test_signer = Secp256r1TestSigner::generate(SignerRole::Admin);
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
