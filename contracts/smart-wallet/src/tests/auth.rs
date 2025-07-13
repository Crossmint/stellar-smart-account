#![cfg(test)]

use soroban_sdk::{map, testutils::BytesN as _, vec, BytesN, IntoVal};

use crate::{
    auth::{
        permissions::SignerRole,
        proof::{SignatureProofs, SignerProof},
    },
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
    wallet::SmartWallet,
};

extern crate std;

#[test]
fn test_auth_ed25519_happy_case() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign(&env, &payload);
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
fn test_auth_ed25519_no_configured_signer() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let wrong_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let (signer_key, proof) = wrong_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);
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
        Ok(err) => assert_eq!(err, Error::SignerNotFound),
    }
}

#[test]
#[should_panic]
fn test_auth_ed25519_wrong_signature() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign(&env, &payload);
    let wrong_proof = if let SignerProof::Ed25519(_) = proof {
        SignerProof::Ed25519(BytesN::random(&env))
    } else {
        panic!("Invalid proof type");
    };
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), wrong_proof.clone())]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_auth_ed25519_no_signatures() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let auth_payloads = SignatureProofs(map![&env,]);
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
        Ok(err) => assert_eq!(err, Error::NoProofsInAuthEntry),
    }
}

#[test]
#[should_panic]
fn test_deploy_without_sufficient_permissions() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Standard);
    env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn test_constructor_duplicate_signers() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let signer1 = test_signer.into_signer(&env);
    let signer2 = test_signer.into_signer(&env); // Same signer key, different instance
    env.register(SmartWallet, (vec![&env, signer1, signer2],));
}

#[test]
fn test_constructor_different_signers_success() {
    let env = setup();
    let test_signer1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let test_signer2 = Ed25519TestSigner::generate(SignerRole::Standard);
    let signer1 = test_signer1.into_signer(&env);
    let signer2 = test_signer2.into_signer(&env);
    env.register(SmartWallet, (vec![&env, signer1, signer2],));
}
