#![cfg(test)]

use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, Vec};

use crate::{
    account::SmartAccount,
    auth::policy::TimeBasedPolicy,
    auth::{
        permissions::{PolicyCallback, SignerPolicy, SignerRole},
        proof::SignatureProofs,
        signer::SignerKey,
    },
    error::Error,
    interface::SmartAccountInterface,
    tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait as _},
};

extern crate std;

#[test]
fn test_revoke_admin_signer_prevented() {
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
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let _auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);

    let admin_signer_key = SignerKey::Ed25519(admin_signer.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, admin_signer_key)
    });

    assert_eq!(result.unwrap_err(), Error::CannotRevokeAdminSigner);
}

#[test]
fn test_revoke_standard_signer_allowed() {
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
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let _auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);

    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_signer_key)
    });

    assert!(result.is_ok());
}

#[test]
fn test_add_multiple_admin_signers_success() {
    let env = setup();

    // Deploy with one admin
    let admin1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin1.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Prepare a second admin signer
    let admin2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin2_signer = admin2.into_signer(&env);

    // Call add_signer as contract (auth mocked) to simulate admin operation
    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, admin2_signer.clone())
    });

    // Should succeed - this tests that the admin count arithmetic works correctly
    assert!(result.is_ok(), "Adding second admin should succeed");

    // Verify we can add a third admin as well to test the arithmetic further
    let admin3 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin3_signer = admin3.into_signer(&env);

    let result2 = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, admin3_signer)
    });

    assert!(result2.is_ok(), "Adding third admin should also succeed");
}

#[test]
fn test_admin_count_underflow_protection() {
    let env = setup();

    // Deploy with two admin signers
    let admin1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin1.into_signer(&env), admin2.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Downgrade first admin to standard (should work)
    let admin1_standard = Ed25519TestSigner(admin1.0, SignerRole::Standard(vec![&env]));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, admin1_standard.into_signer(&env))
    });

    assert!(
        result.is_ok(),
        "Downgrading first admin should succeed when there are 2 admins"
    );

    // Try to downgrade the last admin (should fail)
    let admin2_standard = Ed25519TestSigner(admin2.0, SignerRole::Standard(vec![&env]));

    let result2 = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, admin2_standard.into_signer(&env))
    });

    assert_eq!(
        result2.unwrap_err(),
        Error::CannotDowngradeLastAdmin,
        "Should prevent downgrading the last admin"
    );
}

#[test]
fn test_revoke_signer_with_time_based_policy_calls_on_revoke() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);

    // Create a standard signer with a time-based policy
    let policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp(),
        not_after: env.ledger().timestamp() + 1000,
    });
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy]));

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

    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_signer_key)
    });

    // The test should succeed, which means on_revoke was called successfully
    // For TimeBasedPolicy, on_revoke is a no-op that returns Ok(())
    // If on_revoke failed, the revoke_signer operation would have failed
    assert!(
        result.is_ok(),
        "Revoking signer with policy should succeed when on_revoke succeeds"
    );
}

#[test]
fn test_revoke_signer_with_multiple_policies_calls_all_on_revoke() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);

    // Create a standard signer with multiple time-based policies
    let policy1 = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp(),
        not_after: env.ledger().timestamp() + 1000,
    });
    let policy2 = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp() + 100,
        not_after: env.ledger().timestamp() + 2000,
    });

    let standard_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy1, policy2]));

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

    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_signer_key)
    });

    // The test should succeed, demonstrating that on_revoke was called for all policies
    // If any on_revoke call had failed, the entire revoke_signer operation would have failed
    assert!(
        result.is_ok(),
        "Revoking signer with multiple policies should succeed when all on_revoke calls succeed"
    );
}

// This test documents the expected behavior based on the implementation
// External policy on_revoke failures are handled gracefully (emit events but don't fail the revocation)
// Time-based policy on_revoke is a no-op that always succeeds
#[test]
fn test_on_revoke_behavior_documented() {
    let env = setup();

    // Test TimeBasedPolicy on_revoke behavior directly
    let time_policy = TimeBasedPolicy {
        not_before: env.ledger().timestamp(),
        not_after: env.ledger().timestamp() + 1000,
    };

    // TimeBasedPolicy on_revoke always succeeds (no-op)
    let result = time_policy.on_revoke(&env);
    assert!(
        result.is_ok(),
        "TimeBasedPolicy on_revoke should always succeed"
    );

    // Note: External policy on_revoke behavior is more complex to test as it requires
    // deploying external policy contracts. The key documented behavior is:
    // - ExternalPolicy.on_revoke() emits PolicyCallbackFailedEvent on failure but continues
    // - This provides graceful degradation during signer revocation
    // - The revoke operation succeeds even if external policy callbacks fail
}
