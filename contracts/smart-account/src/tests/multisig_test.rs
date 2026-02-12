use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, IntoVal, Map, Vec};

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
    Ed25519Signer, MultisigMember, MultisigSigner, Signer, SignerKey, SignerRole,
    SmartAccountInterface as _,
};

// ============================================================================
// Helpers
// ============================================================================

fn make_multisig_signer(
    env: &soroban_sdk::Env,
    members: &[&Ed25519TestSigner],
    threshold: u32,
    role: SignerRole,
) -> (Signer, BytesN<32>) {
    let id = BytesN::random(env);
    let mut multisig_members: Vec<MultisigMember> = Vec::new(env);
    for m in members {
        multisig_members.push_back(MultisigMember::Ed25519(Ed25519Signer::new(
            m.public_key(env),
        )));
    }
    let multisig = MultisigSigner::new(id.clone(), multisig_members, threshold);
    (Signer::Multisig(multisig, role), id)
}

fn make_multisig_proof(
    env: &soroban_sdk::Env,
    signers: &[&Ed25519TestSigner],
    payload: &BytesN<32>,
) -> SignerProof {
    let mut member_proofs = Map::new(env);
    for s in signers {
        let (key, proof) = s.sign(env, payload);
        member_proofs.set(key, proof);
    }
    SignerProof::Multisig(member_proofs)
}

/// Register a smart account with an admin + a multisig signer, then try to
/// authorize with the given member subset. Returns the `__check_auth` result.
fn check_multisig_auth(
    env: &soroban_sdk::Env,
    contract_id: &Address,
    multisig_id: &BytesN<32>,
    signing_members: &[&Ed25519TestSigner],
    contexts: &Vec<soroban_sdk::auth::Context>,
) -> Result<(), Error> {
    let payload = BytesN::random(env);
    let proof = make_multisig_proof(env, signing_members, &payload);
    let auth = SignatureProofs(map![env, (SignerKey::Multisig(multisig_id.clone()), proof)]);

    env.try_invoke_contract_check_auth::<Error>(contract_id, &payload, auth.into_val(env), contexts)
        .map(|_| ())
        .map_err(|e| match e {
            Ok(err) => err,
            Err(e) => panic!("{:?}", e),
        })
}

// ============================================================================
// Verification tests
// ============================================================================

#[test]
fn test_multisig_2_of_3_happy_path() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2, m3) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2, &m3], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
    let ctx = vec![&env, get_token_auth_context(&env)];

    // 2 of 3 sign — meets threshold
    check_multisig_auth(&env, &cid, &id, &[&m1, &m2], &ctx).unwrap();
}

#[test]
fn test_multisig_all_sign() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2, m3) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2, &m3], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
    let ctx = vec![&env, get_token_auth_context(&env)];

    // All 3 sign — exceeds threshold
    check_multisig_auth(&env, &cid, &id, &[&m1, &m2, &m3], &ctx).unwrap();
}

#[test]
fn test_multisig_1_of_1() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let m = Ed25519TestSigner::generate(SignerRole::Admin);
    let (signer, id) = make_multisig_signer(&env, &[&m], 1, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
    let ctx = vec![&env, get_token_auth_context(&env)];

    check_multisig_auth(&env, &cid, &id, &[&m], &ctx).unwrap();
}

#[test]
fn test_multisig_threshold_not_met() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2, m3) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2, &m3], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
    let ctx = vec![&env, get_token_auth_context(&env)];

    // Only 1 of 3 signs — below threshold
    let err = check_multisig_auth(&env, &cid, &id, &[&m1], &ctx).unwrap_err();
    assert_eq!(err, Error::MultisigThresholdNotMet);
}

#[test]
#[should_panic]
fn test_multisig_invalid_member_proof() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (key0, _) = m1.sign(&env, &payload);
    let (key1, proof1) = m2.sign(&env, &payload);
    let mut member_proofs = Map::new(&env);
    member_proofs.set(key0, SignerProof::Ed25519(BytesN::random(&env))); // bad sig
    member_proofs.set(key1, proof1);

    let auth = SignatureProofs(map![
        &env,
        (
            SignerKey::Multisig(id),
            SignerProof::Multisig(member_proofs)
        )
    ]);
    // Panics — ed25519_verify panics on bad signature
    env.try_invoke_contract_check_auth::<Error>(
        &cid,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_multisig_unknown_member_key() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let non_member = Ed25519TestSigner::generate(SignerRole::Admin);
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
    let ctx = vec![&env, get_token_auth_context(&env)];

    let err = check_multisig_auth(&env, &cid, &id, &[&m1, &non_member], &ctx).unwrap_err();
    assert_eq!(err, Error::MultisigMemberNotFound);
}

// ============================================================================
// Role tests
// ============================================================================

#[test]
fn test_multisig_admin_role() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );

    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let ctx = vec![
        &env,
        get_update_signer_auth_context(&env, &cid, new_signer.into_signer(&env)),
    ];
    check_multisig_auth(&env, &cid, &id, &[&m1, &m2], &ctx).unwrap();
}

#[test]
fn test_multisig_standard_role() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Standard(vec![&env]));
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );

    // Can authorize token transfers
    let token_ctx = vec![&env, get_token_auth_context(&env)];
    check_multisig_auth(&env, &cid, &id, &[&m1, &m2], &token_ctx).unwrap();

    // Cannot authorize admin operations
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));
    let admin_ctx = vec![
        &env,
        get_update_signer_auth_context(&env, &cid, new_signer.into_signer(&env)),
    ];
    let err = check_multisig_auth(&env, &cid, &id, &[&m1, &m2], &admin_ctx).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

// ============================================================================
// Validation tests
// ============================================================================

#[test]
#[should_panic(expected = "Error(Contract, #47)")]
fn test_multisig_invalid_threshold_zero() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let m = Ed25519TestSigner::generate(SignerRole::Admin);
    let (signer, _) = make_multisig_signer(&env, &[&m], 0, SignerRole::Admin);
    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #47)")]
fn test_multisig_invalid_threshold_exceeds_members() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, _) = make_multisig_signer(&env, &[&m1, &m2], 3, SignerRole::Admin);
    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), signer],
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
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Standard(vec![&env]));
    let key = SignerKey::Multisig(id);

    env.as_contract(&cid, || {
        SmartAccount::add_signer(&env, signer).unwrap();
        assert!(SmartAccount::has_signer(&env, key.clone()).unwrap());
        SmartAccount::revoke_signer(&env, key.clone()).unwrap();
        assert!(!SmartAccount::has_signer(&env, key.clone()).unwrap());
    });
}

#[test]
fn test_constructor_with_multisig_admin() {
    let env = setup();
    let (m1, m2) = (
        Ed25519TestSigner::generate(SignerRole::Admin),
        Ed25519TestSigner::generate(SignerRole::Admin),
    );
    let (signer, id) = make_multisig_signer(&env, &[&m1, &m2], 2, SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (vec![&env, signer], Vec::<Address>::new(&env)),
    );

    // Multisig as sole admin can authorize
    let ctx = vec![&env, get_token_auth_context(&env)];
    check_multisig_auth(&env, &cid, &id, &[&m1, &m2], &ctx).unwrap();
}
