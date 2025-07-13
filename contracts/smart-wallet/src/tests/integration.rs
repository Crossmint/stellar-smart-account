#![cfg(test)]

extern crate std;

use soroban_sdk::{
    map, symbol_short, testutils::Address as _, testutils::BytesN as _, vec, Address, BytesN, Env,
    IntoVal, Val, Vec,
};

use crate::{
    auth::{
        permissions::{SignerPolicy, SignerRole},
        policy::{ContractAllowListPolicy, TimeBasedPolicy},
        proof::SignatureProofs,
    },
    error::Error,
    interface::SmartWalletInterface,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
    wallet::SmartWallet,
};

use contract_factory::{ContractFactory, ContractFactoryClient};
use upgradeable::SmartWalletUpgradeable;

fn create_factory_client<'a>(e: &Env, admin: &Address) -> ContractFactoryClient<'a> {
    let address = e.register(ContractFactory, (admin,));
    ContractFactoryClient::new(e, &address)
}

fn create_mock_salt(e: &Env, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = value;
    BytesN::from_array(e, &bytes)
}

fn setup_factory_roles(e: &Env, client: &ContractFactoryClient, admin: &Address) -> Address {
    let deployer = Address::generate(e);

    // Set role admin for deployer role
    client.set_role_admin(&symbol_short!("deployer"), &symbol_short!("dep_admin"));

    // Grant deployer admin role
    let deployer_admin = Address::generate(e);
    client.grant_role(admin, &deployer_admin, &symbol_short!("dep_admin"));

    // Deployer admin grants deployer role
    client.grant_role(&deployer_admin, &deployer, &symbol_short!("deployer"));

    deployer
}

#[test]
fn test_factory_deployment() {
    let env = setup();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let client = create_factory_client(&env, &admin);

    let new_deployer = Address::generate(&env);
    client.grant_role(&admin, &new_deployer, &symbol_short!("deployer"));

    // Verify the role was granted
    assert!(client
        .has_role(&new_deployer, &symbol_short!("deployer"))
        .is_some());
}

#[test]
fn test_smart_wallet_deployment_through_factory() {
    let env = setup();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let client = create_factory_client(&env, &admin);
    let deployer = setup_factory_roles(&env, &client, &admin);

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);

    let salt = create_mock_salt(&env, 1);
    let predicted_address = client.get_deployed_address(&salt);
    assert!(!predicted_address.to_string().is_empty());

    let wallet_address = env.register_at(
        &predicted_address,
        SmartWallet,
        (vec![&env, admin_signer.into_signer(&env)],),
    );

    assert_eq!(wallet_address, predicted_address);

    // Verify the wallet is properly initialized with the admin signer
    let payload = BytesN::random(&env);
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &wallet_address,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_add_standard_signer() {
    let env = setup();
    env.mock_all_auths();

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, admin_signer.into_signer(&env)],));

    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard);

    let result = env.as_contract(&contract_id, || {
        SmartWallet::add_signer(&env, standard_signer.into_signer(&env))
    });

    assert!(result.is_ok());
}

#[test]
fn test_add_restricted_signer() {
    let env = setup();
    env.mock_all_auths();

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, admin_signer.into_signer(&env)],));

    let current_time = env.ledger().timestamp();
    let time_policy = SignerPolicy::TimeBased(TimeBasedPolicy {
        not_before: current_time,
        not_after: current_time + 1000,
    });

    let restricted_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, time_policy]));

    let result = env.as_contract(&contract_id, || {
        SmartWallet::add_signer(&env, restricted_signer.into_signer(&env))
    });

    assert!(result.is_ok());
}

#[test]
fn test_wallet_upgrade() {
    let env = setup();
    env.mock_all_auths();

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, admin_signer.into_signer(&env)],));

    let new_wasm_bytes =
        soroban_sdk::Bytes::from_slice(&env, crate::test_constants::SMART_WALLET_WASM);
    let new_wasm_hash = env.deployer().upload_contract_wasm(new_wasm_bytes);

    env.as_contract(&contract_id, || SmartWallet::upgrade(&env, new_wasm_hash));
}

#[test]
fn test_external_contract_authorization() {
    let env = setup();
    env.mock_all_auths();

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard);

    let contract_id = env.register(
        SmartWallet,
        (vec![
            &env,
            admin_signer.into_signer(&env),
            standard_signer.into_signer(&env),
        ],),
    );

    let payload = BytesN::random(&env);
    let (signer_key, proof) = standard_signer.sign(&env, &payload);
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
fn test_comprehensive_smart_wallet_lifecycle() {
    let env = setup();
    env.mock_all_auths();

    let factory_admin = Address::generate(&env);
    let factory_client = create_factory_client(&env, &factory_admin);
    let deployer = setup_factory_roles(&env, &factory_client, &factory_admin);

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let wasm_bytes = soroban_sdk::Bytes::from_slice(&env, crate::test_constants::SMART_WALLET_WASM);
    let salt = create_mock_salt(&env, 42);
    let constructor_args: Vec<Val> = vec![
        &env,
        vec![&env, admin_signer.into_signer(&env)].into_val(&env),
    ];

    let predicted_address = factory_client.get_deployed_address(&salt);

    // with the predicted address and verifying it works with the admin signer
    let wallet_address = env.register_at(
        &predicted_address,
        SmartWallet,
        (vec![&env, admin_signer.into_signer(&env)],),
    );

    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard);
    let add_standard_result = env.as_contract(&wallet_address, || {
        SmartWallet::add_signer(&env, standard_signer.into_signer(&env))
    });
    assert!(add_standard_result.is_ok());

    let allowed_contract = Address::generate(&env);
    let allowlist_policy = SignerPolicy::ContractAllowList(ContractAllowListPolicy {
        allowed_contracts: vec![&env, allowed_contract.clone()],
    });
    let restricted_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, allowlist_policy]));

    let add_restricted_result = env.as_contract(&wallet_address, || {
        SmartWallet::add_signer(&env, restricted_signer.into_signer(&env))
    });
    assert!(add_restricted_result.is_ok());

    let new_wasm_bytes =
        soroban_sdk::Bytes::from_slice(&env, crate::test_constants::SMART_WALLET_WASM);
    let new_wasm_hash = env.deployer().upload_contract_wasm(new_wasm_bytes);

    env.as_contract(&wallet_address, || {
        SmartWallet::upgrade(&env, new_wasm_hash)
    });

    let payload = BytesN::random(&env);

    let (standard_key, standard_proof) = standard_signer.sign(&env, &payload);
    let standard_auth = SignatureProofs(map![&env, (standard_key, standard_proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &wallet_address,
        &payload,
        standard_auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    let (restricted_key, restricted_proof) = restricted_signer.sign(&env, &payload);
    let restricted_auth = SignatureProofs(map![&env, (restricted_key, restricted_proof)]);

    let allowed_context =
        soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
            contract: allowed_contract,
            fn_name: "transfer".into_val(&env),
            args: ((), (), 1000).into_val(&env),
        });

    env.try_invoke_contract_check_auth::<Error>(
        &wallet_address,
        &payload,
        restricted_auth.into_val(&env),
        &vec![&env, allowed_context],
    )
    .unwrap();
}
