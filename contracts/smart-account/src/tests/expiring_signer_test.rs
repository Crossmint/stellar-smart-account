#![cfg(test)]

use soroban_sdk::{
    map,
    testutils::{BytesN as _, Ledger as _},
    vec, Address, BytesN, IntoVal, Vec,
};

use crate::{
    account::SmartAccount,
    auth::proof::SignatureProofs,
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
};
use smart_account_interfaces::{SignerKey, SignerRole, SmartAccountInterface as _};

extern crate std;

use ed25519_dalek::Keypair;

// ============================================================================
// Helpers
// ============================================================================

/// Reconstruct an Ed25519TestSigner with the same keypair but a different role.
/// Needed because `ed25519_dalek::Keypair` does not implement `Clone`.
fn with_role(signer: &Ed25519TestSigner, role: SignerRole) -> Ed25519TestSigner {
    let bytes = signer.0.to_bytes();
    Ed25519TestSigner(Keypair::from_bytes(&bytes).unwrap(), role)
}

/// Invoke `__check_auth` and return the result.
fn check_auth(
    env: &soroban_sdk::Env,
    contract_id: &Address,
    signer: &Ed25519TestSigner,
    contexts: &Vec<soroban_sdk::auth::Context>,
) -> Result<(), Error> {
    let payload = BytesN::random(env);
    let (signer_key, proof) = signer.sign(env, &payload);
    let auth = SignatureProofs(map![env, (signer_key, proof)]);
    env.try_invoke_contract_check_auth::<Error>(contract_id, &payload, auth.into_val(env), contexts)
        .map(|_| ())
        .map_err(|e| match e {
            Ok(err) => err,
            Err(e) => panic!("{:?}", e),
        })
}

// ============================================================================
// Authorization tests
// ============================================================================

#[test]
fn test_expiring_signer_authorized_before_expiration() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_token_auth_context(&env)];

    // At timestamp 100, signer with expiration 200 should be authorized
    check_auth(&env, &cid, &expiring, &ctx).unwrap();
}

#[test]
fn test_expiring_signer_authorized_at_expiration_boundary() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_token_auth_context(&env)];

    // At timestamp == expiration, signer is NOT expired (check is `timestamp > expiration`)
    env.ledger().with_mut(|li| li.timestamp = 200);
    check_auth(&env, &cid, &expiring, &ctx).unwrap();
}

#[test]
fn test_expiring_signer_rejected_after_expiration() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_token_auth_context(&env)];

    // At timestamp 201, signer with expiration 200 should be rejected
    env.ledger().with_mut(|li| li.timestamp = 201);
    let err = check_auth(&env, &cid, &expiring, &ctx).unwrap_err();
    assert_eq!(err, Error::SignerExpired);
}

#[test]
fn test_non_expiring_standard_signer_works_at_any_timestamp() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None,0));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_token_auth_context(&env)];

    // Expiration 0 means no expiration — works at any timestamp
    env.ledger().with_mut(|li| li.timestamp = u64::MAX);
    check_auth(&env, &cid, &standard, &ctx).unwrap();
}

// ============================================================================
// Signer management tests
// ============================================================================

#[test]
fn test_add_signer_with_past_expiration_rejected() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Try adding a signer that has already expired
    let expired = Ed25519TestSigner::generate(SignerRole::Standard(None,500));

    env.mock_all_auths();
    let res = env.as_contract(&cid, || SmartAccount::add_signer(&env, expired.into_signer(&env)));
    assert_eq!(res.unwrap_err(), Error::SignerExpired);
}

#[test]
fn test_add_signer_with_current_timestamp_as_expiration_rejected() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Expiration == current timestamp should be rejected (validate_signer_expiration uses <=)
    let at_boundary = Ed25519TestSigner::generate(SignerRole::Standard(None,1000));

    env.mock_all_auths();
    let res =
        env.as_contract(&cid, || SmartAccount::add_signer(&env, at_boundary.into_signer(&env)));
    assert_eq!(res.unwrap_err(), Error::SignerExpired);
}

#[test]
fn test_add_signer_with_future_expiration_succeeds() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let future = Ed25519TestSigner::generate(SignerRole::Standard(None,2000));

    env.mock_all_auths();
    let res = env.as_contract(&cid, || SmartAccount::add_signer(&env, future.into_signer(&env)));
    assert!(res.is_ok());
}

#[test]
fn test_update_signer_extend_expiration() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_token_auth_context(&env)];

    // Advance past original expiration
    env.ledger().with_mut(|li| li.timestamp = 250);
    let err = check_auth(&env, &cid, &expiring, &ctx).unwrap_err();
    assert_eq!(err, Error::SignerExpired);

    // Admin extends the expiration via update_signer
    let extended = with_role(&expiring, SignerRole::Standard(None,500));
    env.mock_all_auths();
    env.as_contract(&cid, || {
        SmartAccount::update_signer(&env, extended.into_signer(&env))
    })
    .unwrap();

    // Now the signer should work again
    check_auth(&env, &cid, &expiring, &ctx).unwrap();
}

#[test]
fn test_update_signer_remove_expiration() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Remove expiration (set to 0)
    let no_expiry = with_role(&expiring, SignerRole::Standard(None,0));
    env.mock_all_auths();
    env.as_contract(&cid, || {
        SmartAccount::update_signer(&env, no_expiry.into_signer(&env))
    })
    .unwrap();

    // Signer works even far in the future
    env.ledger().with_mut(|li| li.timestamp = u64::MAX);
    let ctx = vec![&env, get_token_auth_context(&env)];
    check_auth(&env, &cid, &expiring, &ctx).unwrap();
}

#[test]
fn test_revoke_expired_signer_succeeds() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Advance past expiration
    env.ledger().with_mut(|li| li.timestamp = 300);

    // Admin can still revoke an expired signer
    let signer_key = SignerKey::Ed25519(expiring.public_key(&env));
    env.mock_all_auths();
    let res = env.as_contract(&cid, || SmartAccount::revoke_signer(&env, signer_key.clone()));
    assert!(res.is_ok());

    // Verify signer no longer exists
    let exists = env.as_contract(&cid, || SmartAccount::has_signer(&env, signer_key));
    assert!(!exists.unwrap());
}

#[test]
fn test_get_signer_returns_expired_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Advance past expiration
    env.ledger().with_mut(|li| li.timestamp = 300);

    // get_signer still returns the expired signer (data exists in storage)
    let signer_key = SignerKey::Ed25519(expiring.public_key(&env));
    let result = env.as_contract(&cid, || SmartAccount::get_signer(&env, signer_key));
    assert!(result.is_ok());
}

// ============================================================================
// Constructor tests
// ============================================================================

#[test]
fn test_constructor_with_expiring_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));

    let cid = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expiring.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Verify the expiring signer was registered
    let signer_key = SignerKey::Ed25519(expiring.public_key(&env));
    let exists = env.as_contract(&cid, || SmartAccount::has_signer(&env, signer_key));
    assert!(exists.unwrap());
}

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn test_constructor_rejects_already_expired_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expired = Ed25519TestSigner::generate(SignerRole::Standard(None,500));

    // Should panic because the signer is already expired at construction time
    env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), expired.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
}

// ============================================================================
// Edge case: expired signer does not block valid signers
// ============================================================================

#[test]
fn test_expired_signer_does_not_block_other_signers() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 100);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let expiring = Ed25519TestSigner::generate(SignerRole::Standard(None,200));
    let permanent = Ed25519TestSigner::generate(SignerRole::Standard(None,0));

    let cid = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                expiring.into_signer(&env),
                permanent.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    // Advance past expiring signer's expiration
    env.ledger().with_mut(|li| li.timestamp = 300);

    let ctx = vec![&env, get_token_auth_context(&env)];

    // The expired signer fails
    let err = check_auth(&env, &cid, &expiring, &ctx).unwrap_err();
    assert_eq!(err, Error::SignerExpired);

    // But the permanent signer still works fine
    check_auth(&env, &cid, &permanent, &ctx).unwrap();

    // And admin still works fine
    check_auth(&env, &cid, &admin, &ctx).unwrap();
}
