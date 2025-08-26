#![cfg(test)]

use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, Vec};

use crate::{
    account::SmartAccount,
    auth::{permissions::SignerRole, proof::SignatureProofs, signer::SignerKey},
    error::Error,
    interface::SmartAccountInterface,
    tests::test_utils::{
        budget_snapshot, print_budget_delta, setup, Ed25519TestSigner, TestSignerTrait as _,
    },
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
    let b = budget_snapshot(&env);
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, admin_signer_key)
    });
    let a = budget_snapshot(&env);
    print_budget_delta("revoke_signer:admin", &b, &a);

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
    let b = budget_snapshot(&env);
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_signer_key)
    });
    let a = budget_snapshot(&env);
    print_budget_delta("revoke_signer:standard", &b, &a);

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
    let b = budget_snapshot(&env);
    let result = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, admin2_signer.clone())
    });
    let a = budget_snapshot(&env);
    print_budget_delta("add_signer:admin2", &b, &a);

    // Should succeed - this tests that the admin count arithmetic works correctly
    assert!(result.is_ok(), "Adding second admin should succeed");

    // Verify we can add a third admin as well to test the arithmetic further
    let admin3 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin3_signer = admin3.into_signer(&env);

    let b = budget_snapshot(&env);
    let result2 = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, admin3_signer)
    });
    let a = budget_snapshot(&env);
    print_budget_delta("add_signer:admin3", &b, &a);

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
    let b = budget_snapshot(&env);
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, admin1_standard.into_signer(&env))
    });
    let a = budget_snapshot(&env);
    print_budget_delta("update_signer:admin1_to_standard", &b, &a);

    assert!(
        result.is_ok(),
        "Downgrading first admin should succeed when there are 2 admins"
    );

    // Try to downgrade the last admin (should fail)
    let admin2_standard = Ed25519TestSigner(admin2.0, SignerRole::Standard(vec![&env]));

    let b = budget_snapshot(&env);
    let result2 = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, admin2_standard.into_signer(&env))
    });
    let a = budget_snapshot(&env);
    print_budget_delta("update_signer:admin2_to_standard", &b, &a);

    assert_eq!(
        result2.unwrap_err(),
        Error::CannotDowngradeLastAdmin,
        "Should prevent downgrading the last admin"
    );
}
