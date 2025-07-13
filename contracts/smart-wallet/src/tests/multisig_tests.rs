#![cfg(test)]

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{map, testutils::BytesN as _, vec, BytesN, IntoVal, Map};

use crate::{
    auth::{
        permissions::SignerRole,
        proof::{SignatureProofs, SignerProof},
        signers::MultisigSigner,
    },
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, MultisigTestSigner, TestSignerTrait as _},
    wallet::SmartWallet,
};

extern crate std;

#[test]
fn test_multisig_signer_creation_valid() {
    let env = setup();
    let public_keys = vec![
        &env,
        BytesN::random(&env),
        BytesN::random(&env),
        BytesN::random(&env),
    ];

    let multisig_signer = MultisigSigner::new(public_keys, 2);
    assert!(multisig_signer.is_ok());

    let signer = multisig_signer.unwrap();
    assert_eq!(signer.threshold, 2);
    assert_eq!(signer.public_keys.len(), 3);
}

#[test]
fn test_multisig_signer_creation_invalid_threshold_zero() {
    let env = setup();
    let public_keys = vec![&env, BytesN::random(&env), BytesN::random(&env)];

    let result = MultisigSigner::new(public_keys, 0);
    assert_eq!(result.unwrap_err(), Error::InvalidThreshold);
}

#[test]
fn test_multisig_signer_creation_invalid_threshold_too_high() {
    let env = setup();
    let public_keys = vec![&env, BytesN::random(&env), BytesN::random(&env)];

    let result = MultisigSigner::new(public_keys, 3);
    assert_eq!(result.unwrap_err(), Error::InvalidThreshold);
}

#[test]
fn test_multisig_signer_creation_empty_keys() {
    let env = setup();
    let public_keys = vec![&env];

    let result = MultisigSigner::new(public_keys, 1);
    assert_eq!(result.unwrap_err(), Error::EmptyPublicKeysList);
}

#[test]
fn test_auth_multisig_happy_case() {
    let env = setup();
    let multisig_signer = MultisigTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartWallet,
        (vec![&env, multisig_signer.into_signer(&env)],),
    );

    let payload = BytesN::random(&env);
    let (signer_key, proof) = multisig_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_auth_multisig_insufficient_signatures() {
    let env = setup();
    let multisig_signer = MultisigTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartWallet,
        (vec![&env, multisig_signer.into_signer(&env)],),
    );

    let payload = BytesN::random(&env);

    let mut signatures = Map::new(&env);
    signatures.set(0u32, BytesN::random(&env));
    let insufficient_proof = SignerProof::Multisig(signatures);

    let signer_key = multisig_signer.into_signer(&env).into();
    let auth_payloads = SignatureProofs(map![&env, (signer_key, insufficient_proof)]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InsufficientSignatures),
    }
}

#[test]
fn test_auth_multisig_invalid_signer_index() {
    let env = setup();
    let multisig_signer = MultisigTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartWallet,
        (vec![&env, multisig_signer.into_signer(&env)],),
    );

    let payload = BytesN::random(&env);

    let mut signatures = Map::new(&env);
    signatures.set(10u32, BytesN::random(&env));
    signatures.set(11u32, BytesN::random(&env));
    let invalid_proof = SignerProof::Multisig(signatures);

    let signer_key = multisig_signer.into_signer(&env).into();
    let auth_payloads = SignatureProofs(map![&env, (signer_key, invalid_proof)]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InvalidSignerIndex),
    }
}

#[test]
fn test_auth_multisig_wrong_proof_type() {
    let env = setup();
    let multisig_signer = MultisigTestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartWallet,
        (vec![&env, multisig_signer.into_signer(&env)],),
    );

    let payload = BytesN::random(&env);

    let wrong_proof = SignerProof::Ed25519(BytesN::random(&env));
    let signer_key = multisig_signer.into_signer(&env).into();
    let auth_payloads = SignatureProofs(map![&env, (signer_key, wrong_proof)]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InvalidProofType),
    }
}

#[test]
fn test_auth_multisig_mixed_with_ed25519() {
    let env = setup();
    let multisig_signer = MultisigTestSigner::generate(SignerRole::Admin);
    let ed25519_signer =
        crate::tests::test_utils::Ed25519TestSigner::generate(SignerRole::Standard);

    let contract_id = env.register(
        SmartWallet,
        (vec![
            &env,
            multisig_signer.into_signer(&env),
            ed25519_signer.into_signer(&env),
        ],),
    );

    let payload = BytesN::random(&env);
    let (multisig_key, multisig_proof) = multisig_signer.sign(&env, &payload);
    let (ed25519_key, ed25519_proof) = ed25519_signer.sign(&env, &payload);

    let auth_payloads = SignatureProofs(map![
        &env,
        (multisig_key, multisig_proof),
        (ed25519_key, ed25519_proof)
    ]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_multisig_signer_key_generation_deterministic() {
    let env = setup();
    let public_keys = vec![
        &env,
        BytesN::from_array(&env, &[1u8; 32]),
        BytesN::from_array(&env, &[2u8; 32]),
        BytesN::from_array(&env, &[3u8; 32]),
    ];

    let signer1 = MultisigSigner::new(public_keys.clone(), 2).unwrap();
    let signer2 = MultisigSigner::new(public_keys, 2).unwrap();

    let key1: crate::auth::signer::SignerKey = signer1.into();
    let key2: crate::auth::signer::SignerKey = signer2.into();

    assert_eq!(key1, key2);
}

#[test]
fn test_multisig_signer_key_generation_different_threshold() {
    let env = setup();
    let public_keys = vec![
        &env,
        BytesN::from_array(&env, &[1u8; 32]),
        BytesN::from_array(&env, &[2u8; 32]),
        BytesN::from_array(&env, &[3u8; 32]),
    ];

    let signer1 = MultisigSigner::new(public_keys.clone(), 2).unwrap();
    let signer2 = MultisigSigner::new(public_keys, 3).unwrap();

    let key1: crate::auth::signer::SignerKey = signer1.into();
    let key2: crate::auth::signer::SignerKey = signer2.into();

    assert_ne!(key1, key2);
}
