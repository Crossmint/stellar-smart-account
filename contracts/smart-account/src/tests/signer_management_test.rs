#![cfg(test)]

use soroban_sdk::{map, testutils::BytesN as _, vec, Address, BytesN, Vec};

use crate::{
    account::SmartAccount,
    auth::{permissions::SignerRole, proof::SignatureProofs, signer::SignerKey},
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
fn test_has_signer_returns_true_when_signer_exists() {
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

    let admin_signer_key = SignerKey::Ed25519(admin_signer.public_key(&env));
    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));

    // Test that has_signer returns true for existing signers
    let admin_result = env.as_contract(&contract_id, || {
        SmartAccount::has_signer(&env, admin_signer_key)
    });

    let standard_result = env.as_contract(&contract_id, || {
        SmartAccount::has_signer(&env, standard_signer_key)
    });

    assert!(admin_result.is_ok());
    assert!(admin_result.unwrap());
    assert!(standard_result.is_ok());
    assert!(standard_result.unwrap());
}

#[test]
fn test_has_signer_returns_false_when_signer_does_not_exist() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let non_existent_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let non_existent_signer_key = SignerKey::Ed25519(non_existent_signer.public_key(&env));

    // Test that has_signer returns false for non-existent signer
    let result = env.as_contract(&contract_id, || {
        SmartAccount::has_signer(&env, non_existent_signer_key)
    });

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_get_signer_returns_signer_when_exists() {
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

    let admin_signer_key = SignerKey::Ed25519(admin_signer.public_key(&env));
    let standard_signer_key = SignerKey::Ed25519(standard_signer.public_key(&env));
    let expected_admin_signer = admin_signer.into_signer(&env);
    let expected_standard_signer = standard_signer.into_signer(&env);

    // Test that get_signer returns the correct signer for existing signers
    let admin_result = env.as_contract(&contract_id, || {
        SmartAccount::get_signer(&env, admin_signer_key)
    });

    let standard_result = env.as_contract(&contract_id, || {
        SmartAccount::get_signer(&env, standard_signer_key)
    });

    assert!(admin_result.is_ok());
    assert_eq!(admin_result.unwrap(), expected_admin_signer);
    assert!(standard_result.is_ok());
    assert_eq!(standard_result.unwrap(), expected_standard_signer);
}

#[test]
fn test_get_signer_returns_error_when_signer_does_not_exist() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let non_existent_signer = Ed25519TestSigner::generate(SignerRole::Standard(vec![&env]));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let non_existent_signer_key = SignerKey::Ed25519(non_existent_signer.public_key(&env));

    // Test that get_signer returns SignerNotFound error for non-existent signer
    let result = env.as_contract(&contract_id, || {
        SmartAccount::get_signer(&env, non_existent_signer_key)
    });

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::SignerNotFound);
}
