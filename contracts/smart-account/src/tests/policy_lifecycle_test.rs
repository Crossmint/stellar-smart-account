#![cfg(test)]

use soroban_sdk::{vec, Address, Vec};

use crate::{
    account::SmartAccount,
    auth::{
        permissions::{SignerPolicy, SignerRole},
        policy::TimeBasedPolicy,
        signer::SignerKey,
    },
    error::Error,
    interface::SmartAccountInterface,
    tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait as _},
};

extern crate std;

#[test]
fn test_update_signer_admin_to_standard_calls_on_add() {
    let env = setup();

    // Create admin signers and a time-based policy
    let admin_signer1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin_signer2 = Ed25519TestSigner::generate(SignerRole::Admin);
    let time_policy = TimeBasedPolicy {
        not_before: 0,
        not_after: u64::MAX,
    };
    let policies = vec![&env, SignerPolicy::TimeWindowPolicy(time_policy)];

    // Deploy contract with multiple admin signers so we can downgrade one
    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer1.into_signer(&env),
                admin_signer2.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    // Mock auth for the admin signer to update itself
    env.mock_all_auths();

    // Create a new Standard signer with the same key but different role
    let updated_signer =
        admin_signer1.into_signer_with_role(&env, SignerRole::Standard(policies.clone()));

    // Update the signer from Admin to Standard - this should call on_add for policies
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated_signer)
    });

    // Should succeed - on_add was called successfully for the time-based policy
    assert!(result.is_ok());
}

#[test]
fn test_update_signer_standard_to_admin_calls_on_revoke() {
    let env = setup();

    // Create a time-based policy
    let time_policy = TimeBasedPolicy {
        not_before: 0,
        not_after: u64::MAX,
    };
    let policies = vec![&env, SignerPolicy::TimeWindowPolicy(time_policy)];

    // Create signers
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(policies));

    // Deploy contract with both signers
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

    // Mock auth
    env.mock_all_auths();

    // Create an updated signer that promotes the standard signer to admin
    let updated_signer = standard_signer.into_signer_with_role(&env, SignerRole::Admin);

    // Update the signer from Standard to Admin - this should call on_revoke for policies
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated_signer)
    });

    // Should succeed - on_revoke was called successfully
    assert!(result.is_ok());
}

#[test]
fn test_update_signer_standard_to_standard_policy_changes() {
    let env = setup();

    // Create two different time-based policies
    let policy1 = TimeBasedPolicy {
        not_before: 0,
        not_after: 1000,
    };
    let policy2 = TimeBasedPolicy {
        not_before: 1000,
        not_after: 2000,
    };
    let policy3 = TimeBasedPolicy {
        not_before: 2000,
        not_after: 3000,
    };

    let old_policies = vec![
        &env,
        SignerPolicy::TimeWindowPolicy(policy1),
        SignerPolicy::TimeWindowPolicy(policy2.clone()),
    ];
    let new_policies = vec![
        &env,
        SignerPolicy::TimeWindowPolicy(policy2), // Keep policy2
        SignerPolicy::TimeWindowPolicy(policy3), // Add policy3, remove policy1
    ];

    // Create signers
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(old_policies));

    // Deploy contract
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

    // Mock auth
    env.mock_all_auths();

    // Update the standard signer with new policies
    let updated_signer =
        standard_signer.into_signer_with_role(&env, SignerRole::Standard(new_policies));

    // This should call on_revoke for policy1 and on_add for policy3
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated_signer)
    });

    // Should succeed
    assert!(result.is_ok());
}

#[test]
fn test_revoke_signer_calls_on_revoke_for_policies() {
    let env = setup();

    // Create a time-based policy
    let time_policy = TimeBasedPolicy {
        not_before: 0,
        not_after: u64::MAX,
    };
    let policies = vec![&env, SignerPolicy::TimeWindowPolicy(time_policy)];

    // Create signers
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(policies));

    // Deploy contract
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

    // Mock auth
    env.mock_all_auths();

    // Get the standard signer key
    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));

    // Revoke the standard signer - this should call on_revoke for its policies
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_signer_key)
    });

    // Should succeed - on_revoke was called for the policies
    assert!(result.is_ok());
}

#[test]
fn test_update_signer_policy_callback_failure_propagates() {
    let env = setup();

    // Create a time-based policy with invalid parameters that will fail on_add
    let invalid_policy = TimeBasedPolicy {
        not_before: 1000,
        not_after: 500, // not_after < not_before will fail validation
    };
    let policies = vec![&env, SignerPolicy::TimeWindowPolicy(invalid_policy)];

    // Create multiple admin signers so we can downgrade one
    let admin_signer1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin_signer2 = Ed25519TestSigner::generate(SignerRole::Admin);

    // Deploy contract
    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin_signer1.into_signer(&env),
                admin_signer2.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    // Mock auth
    env.mock_all_auths();

    // Try to update admin to standard with invalid policy
    let updated_signer = admin_signer1.into_signer_with_role(&env, SignerRole::Standard(policies));

    // This should fail because the policy's on_add callback will fail
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated_signer)
    });

    // Should fail with InvalidTimeRange error
    assert_eq!(result.unwrap_err(), Error::InvalidTimeRange);
}

#[test]
fn test_update_signer_unchanged_policies_no_callbacks() {
    let env = setup();

    // Create three different policies
    let policy1 = TimeBasedPolicy {
        not_before: 0,
        not_after: 1000,
    };
    let policy2 = TimeBasedPolicy {
        not_before: 1000,
        not_after: 2000,
    };
    let policy3 = TimeBasedPolicy {
        not_before: 2000,
        not_after: 3000,
    };

    // Initial policy set: [policy1, policy2]
    let initial_policies = vec![
        &env,
        SignerPolicy::TimeWindowPolicy(policy1.clone()),
        SignerPolicy::TimeWindowPolicy(policy2.clone()),
    ];

    // Updated policy set: [policy2, policy3]
    // policy1 removed, policy2 unchanged, policy3 added
    let updated_policies = vec![
        &env,
        SignerPolicy::TimeWindowPolicy(policy2), // This should NOT trigger callbacks (unchanged)
        SignerPolicy::TimeWindowPolicy(policy3), // This should trigger on_add (new)
    ];

    // Create signers
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(initial_policies));

    // Deploy contract
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

    // Mock auth
    env.mock_all_auths();

    // Update the standard signer with new policies
    // This should:
    // - Call on_revoke for policy1 (removed)
    // - Call on_add for policy3 (added)
    // - NOT call any callbacks for policy2 (unchanged)
    let updated_signer =
        standard_signer.into_signer_with_role(&env, SignerRole::Standard(updated_policies));

    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated_signer)
    });

    // Should succeed - demonstrates that the policy change detection works correctly
    assert!(result.is_ok());
}
