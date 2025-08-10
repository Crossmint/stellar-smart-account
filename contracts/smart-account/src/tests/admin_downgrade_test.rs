#![cfg(test)]

use soroban_sdk::{vec, Address, Vec};

use crate::{
    account::SmartAccount,
    auth::permissions::SignerRole,
    interface::SmartAccountInterface,
    tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait as _},
    error::Error,
};

#[test]
fn test_cannot_downgrade_last_admin() {
    let env = setup();

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, admin_signer.into_signer(&env)], Vec::<Address>::new(&env)),
    );

    let downgraded = Ed25519TestSigner::from_public_key(
        admin_signer.public_key(&env),
        SignerRole::Standard(vec![&env]),
    )
    .into_signer(&env);

    env.mock_all_auths();
    let res = env.as_contract(&contract_id, || SmartAccount::update_signer(&env, downgraded));
    assert_eq!(res.unwrap_err(), Error::CannotDowngradeLastAdmin);
}

#[test]
fn test_can_downgrade_admin_if_another_admin_exists() {
    let env = setup();

    let admin1 = Ed25519TestSigner::generate(SignerRole::Admin);
    let admin2 = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin1.into_signer(&env), admin2.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let downgraded = Ed25519TestSigner::from_public_key(
        admin2.public_key(&env),
        SignerRole::Standard(vec![&env]),
    )
    .into_signer(&env);

    env.mock_all_auths();
    let res = env.as_contract(&contract_id, || SmartAccount::update_signer(&env, downgraded));
    assert!(res.is_ok());
}
