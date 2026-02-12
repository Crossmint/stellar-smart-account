use soroban_sdk::Vec;
use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, IntoVal};

use crate::{
    account::SmartAccount,
    auth::proof::{SignatureProofs, SignerProof},
    error::Error,
    tests::test_utils::{
        get_token_auth_context, get_update_signer_auth_context, setup, Ed25519TestSigner,
        TestSignerTrait as _,
    },
};
use smart_account_interfaces::{
    Ed25519Signer, MultisigMember, MultisigSigner, SmartAccountInterface as _, Signer, SignerKey,
    SignerRole,
};

fn make_multisig_signer(
    env: &soroban_sdk::Env,
    members: &[&Ed25519TestSigner],
    threshold: u32,
    role: SignerRole,
) -> (Signer, BytesN<32>) {
    let id = BytesN::random(env);
    let mut multisig_members: Vec<MultisigMember> = Vec::new(env);
    for m in members {
        multisig_members.push_back(MultisigMember::Ed25519(Ed25519Signer::new(m.public_key(env))));
    }
    let multisig = MultisigSigner::new(id.clone(), multisig_members, threshold);
    (Signer::Multisig(multisig, role), id)
}

fn make_multisig_proof(
    env: &soroban_sdk::Env,
    signers: &[&Ed25519TestSigner],
    payload: &BytesN<32>,
) -> SignerProof {
    let mut member_proofs = soroban_sdk::Map::new(env);
    for s in signers {
        let (key, proof) = s.sign(env, payload);
        member_proofs.set(key, proof);
    }
    SignerProof::Multisig(member_proofs)
}

// ============================================================================
// Happy path tests
// ============================================================================

#[test]
fn test_multisig_2_of_3_happy_path() {
    let env = setup();

    // Create an admin signer (required for account init)
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);

    // Create 3 members for the multisig
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin); // role ignored
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member3 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2, &member3], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    let multisig_proof = make_multisig_proof(&env, &[&member1, &member2], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_multisig_all_sign() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member3 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2, &member3], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    let multisig_proof = make_multisig_proof(&env, &[&member1, &member2, &member3], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_multisig_1_of_1() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member], 1, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    let multisig_proof = make_multisig_proof(&env, &[&member], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// Failure tests
// ============================================================================

#[test]
fn test_multisig_threshold_not_met() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member3 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2, &member3], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    // Only 1 of 3 signs, but threshold is 2
    let multisig_proof = make_multisig_proof(&env, &[&member1], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

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
        Ok(err) => assert_eq!(err, Error::MultisigThresholdNotMet),
    }
}

#[test]
#[should_panic]
fn test_multisig_invalid_member_proof() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);

    // Create proof with member1's key but a random (invalid) signature
    let (member1_key, _) = member1.sign(&env, &payload);
    let (member2_key, member2_proof) = member2.sign(&env, &payload);
    let invalid_proof = SignerProof::Ed25519(BytesN::random(&env));

    let mut member_proofs = soroban_sdk::Map::new(&env);
    member_proofs.set(member1_key, invalid_proof);
    member_proofs.set(member2_key, member2_proof);
    let multisig_proof = SignerProof::Multisig(member_proofs);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    // Should panic because ed25519_verify panics on bad signature
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_multisig_unknown_member_key() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let non_member = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    // Include a non-member's proof
    let multisig_proof = make_multisig_proof(&env, &[&member1, &non_member], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

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
        Ok(err) => assert_eq!(err, Error::MultisigMemberNotFound),
    }
}

// ============================================================================
// Role tests
// ============================================================================

#[test]
fn test_multisig_admin_role() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2], 2, SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    let multisig_proof = make_multisig_proof(&env, &[&member1, &member2], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    // Admin multisig can authorize admin operations (update_signer)
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
fn test_multisig_standard_role() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) = make_multisig_signer(
        &env,
        &[&member1, &member2],
        2,
        SignerRole::Standard(vec![&env]),
    );

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id.clone());
    let multisig_proof = make_multisig_proof(&env, &[&member1, &member2], &payload);

    // Standard multisig can authorize token transfers
    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    // But cannot authorize admin operations
    let payload2 = BytesN::random(&env);
    let multisig_key2 = SignerKey::Multisig(multisig_id);
    let multisig_proof2 = make_multisig_proof(&env, &[&member1, &member2], &payload2);
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let auth_payloads2 = SignatureProofs(map![&env, (multisig_key2, multisig_proof2)]);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload2,
            auth_payloads2.into_val(&env),
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
// Validation tests
// ============================================================================

#[test]
#[should_panic(expected = "Error(Contract, #47)")]
fn test_multisig_invalid_threshold_zero() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, _) = make_multisig_signer(&env, &[&member], 0, SignerRole::Admin);

    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #47)")]
fn test_multisig_invalid_threshold_exceeds_members() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, _) =
        make_multisig_signer(&env, &[&member1, &member2], 3, SignerRole::Admin);

    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[test]
fn test_add_and_revoke_multisig_signer() {
    let env = setup();
    env.mock_all_auths();

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let (multisig_signer, multisig_id) = make_multisig_signer(
        &env,
        &[&member1, &member2],
        2,
        SignerRole::Standard(vec![&env]),
    );
    let multisig_key = SignerKey::Multisig(multisig_id);

    // Add multisig signer
    env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, multisig_signer).unwrap();
    });

    // Verify it exists
    env.as_contract(&contract_id, || {
        assert!(SmartAccount::has_signer(&env, multisig_key.clone()).unwrap());
    });

    // Revoke it
    env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, multisig_key.clone()).unwrap();
    });

    // Verify it's gone
    env.as_contract(&contract_id, || {
        assert!(!SmartAccount::has_signer(&env, multisig_key.clone()).unwrap());
    });
}

#[test]
fn test_constructor_with_multisig_admin() {
    let env = setup();
    let member1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let member2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let (multisig_signer, multisig_id) =
        make_multisig_signer(&env, &[&member1, &member2], 2, SignerRole::Admin);

    // Deploy with only a multisig admin — no standalone admin
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, multisig_signer],
            Vec::<Address>::new(&env),
        ),
    );

    // Verify multisig can authorize
    let payload = BytesN::random(&env);
    let multisig_key = SignerKey::Multisig(multisig_id);
    let multisig_proof = make_multisig_proof(&env, &[&member1, &member2], &payload);

    let auth_payloads = SignatureProofs(map![&env, (multisig_key, multisig_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}
