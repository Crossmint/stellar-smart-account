use soroban_sdk::Vec;
use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, IntoVal};

use crate::{
    account::SmartAccount,
    auth::{
        permissions::{SignerPolicy, SignerRole},
        policy::TimeBasedPolicy,
        proof::{SignatureProofs, SignerProof},
    },
    error::Error,
    tests::test_utils::{
        get_token_auth_context, get_update_signer_auth_context, setup, Ed25519TestSigner,
        TestSignerTrait as _,
    },
};

extern crate std;

#[test]
fn test_auth_ed25519_happy_case() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
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
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
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
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
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
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
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
    let test_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    env.register(
        SmartAccount,
        (
            vec![&env, test_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
}

// ============================================================================
// ============================================================================

#[test]
fn test_auth_multi_signature_admin_and_standard() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);
    let (standard_key, standard_proof) = standard_signer.sign(&env, &payload);

    let auth_payloads = SignatureProofs(map![
        &env,
        (admin_key.clone(), admin_proof.clone()),
        (standard_key.clone(), standard_proof.clone())
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
fn test_auth_multi_signature_only_admin_needed() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);

    let auth_payloads = SignatureProofs(map![&env, (admin_key.clone(), admin_proof.clone())]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_auth_multi_signature_only_standard_needed() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (standard_key, standard_proof) = standard_signer.sign(&env, &payload);

    let auth_payloads = SignatureProofs(map![&env, (standard_key.clone(), standard_proof.clone())]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// ============================================================================

#[test]
fn test_auth_admin_can_update_signers() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (admin_key.clone(), admin_proof.clone())]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![
            &env,
            get_update_signer_auth_context(&env, &contract_id, new_signer.into_signer(&env)),
        ],
    )
    .unwrap();
}

#[test]
fn test_auth_standard_cannot_update_signers() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (standard_key, standard_proof) = standard_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (standard_key.clone(), standard_proof.clone())]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![
                &env,
                get_update_signer_auth_context(&env, &contract_id, new_signer.into_signer(&env)),
            ],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InsufficientPermissions),
    }
}

// ============================================================================
// ============================================================================

#[test]
fn test_auth_time_based_policy_within_window() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);

    let current_time = env.ledger().timestamp();
    let time_policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: current_time,
        not_after: current_time + 100,
    });

    let restricted_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, time_policy]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                restricted_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (restricted_key, restricted_proof) = restricted_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![
        &env,
        (restricted_key.clone(), restricted_proof.clone())
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
fn test_auth_time_based_policy_outside_window() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);

    let current_time = env.ledger().timestamp();
    let time_policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: current_time + 1000,
        not_after: current_time + 2000,
    });

    let restricted_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, time_policy]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                restricted_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (restricted_key, restricted_proof) = restricted_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![
        &env,
        (restricted_key.clone(), restricted_proof.clone())
    ]);

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
        Ok(err) => assert_eq!(err, Error::InsufficientPermissions),
    }
}

// ============================================================================
// ============================================================================

#[test]
fn test_auth_mixed_valid_invalid_signatures() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);
    let (standard_key, _) = standard_signer.sign(&env, &payload);

    let invalid_proof = SignerProof::Ed25519(BytesN::random(&env));

    let auth_payloads = SignatureProofs(map![
        &env,
        (admin_key.clone(), admin_proof.clone()),
        (standard_key.clone(), invalid_proof)
    ]);

    let _ = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err();
}

#[test]
fn test_auth_multiple_contexts_partial_authorization() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer.into_signer(&env),
                standard_signer.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (standard_key, standard_proof) = standard_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (standard_key.clone(), standard_proof.clone())]);

    let contexts = vec![
        &env,
        get_token_auth_context(&env),
        get_update_signer_auth_context(&env, &contract_id, new_signer.into_signer(&env)),
    ];

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &contexts,
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InsufficientPermissions),
    }
}

#[test]
fn test_auth_idempotency() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (admin_key.clone(), admin_proof.clone())]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.clone().into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn test_constructor_duplicate_signers() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let signer1 = test_signer.into_signer(&env);
    let signer2 = test_signer.into_signer(&env); // Same signer key, different instance
    env.register(
        SmartAccount,
        (vec![&env, signer1, signer2], Vec::<Address>::new(&env)),
    );
}

#[test]
fn test_constructor_different_signers_success() {
    let env = setup();
    let test_signer1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let test_signer2 = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let signer1 = test_signer1.into_signer(&env);
    let signer2 = test_signer2.into_signer(&env);
    env.register(
        SmartAccount,
        (vec![&env, signer1, signer2], Vec::<Address>::new(&env)),
    );
}
