#![cfg(test)]

extern crate std;

use soroban_sdk::{
    symbol_short, testutils::Address as _, vec, Address, BytesN, Env, IntoVal, Val, Vec,
};

use crate::test_constants::SMART_ACCOUNT_WASM;
use crate::{ContractDeploymentArgs, ContractFactory, ContractFactoryClient};

fn create_factory_client<'a>(e: &Env, admin: &Address) -> ContractFactoryClient<'a> {
    let address = e.register(ContractFactory, (admin,));
    ContractFactoryClient::new(e, &address)
}

pub struct TestAccounts {
    pub deployer_admin: Address,
    pub deployer1: Address,
    pub deployer2: Address,
    pub outsider: Address,
}

fn setup_roles(e: &Env, client: &ContractFactoryClient, admin: &Address) -> TestAccounts {
    let deployer_admin = Address::generate(e);
    let deployer1 = Address::generate(e);
    let deployer2 = Address::generate(e);
    let outsider = Address::generate(e);

    // Set role admin for deployer role
    client.set_role_admin(&symbol_short!("deployer"), &symbol_short!("dep_admin"));

    // Grant deployer admin role
    client.grant_role(admin, &deployer_admin, &symbol_short!("dep_admin"));

    // Deployer admin grants deployer roles
    client.grant_role(&deployer_admin, &deployer1, &symbol_short!("deployer"));
    client.grant_role(&deployer_admin, &deployer2, &symbol_short!("deployer"));

    TestAccounts {
        deployer_admin,
        deployer1,
        deployer2,
        outsider,
    }
}

// Helper function to create a mock salt
fn create_mock_salt(e: &Env, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = value; // Make it unique
    BytesN::from_array(e, &bytes)
}

#[test]
fn test_constructor_sets_admin() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    // Admin should be able to grant roles
    let new_deployer = Address::generate(&e);

    client.grant_role(&admin, &new_deployer, &symbol_short!("deployer"));

    // Verify the role was granted
    assert!(client
        .has_role(&new_deployer, &symbol_short!("deployer"))
        .is_some());
}

#[test]
fn test_deployers_have_correct_roles() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);

    // Verify deployer1 has the deployer role
    assert!(client
        .has_role(&accounts.deployer1, &symbol_short!("deployer"))
        .is_some());

    // Verify deployer2 has the deployer role
    assert!(client
        .has_role(&accounts.deployer2, &symbol_short!("deployer"))
        .is_some());

    // Verify outsider does not have the deployer role
    assert!(client
        .has_role(&accounts.outsider, &symbol_short!("deployer"))
        .is_none());
}

#[test]
fn test_non_deployers_lack_role() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);

    // Outsider should not have the deployer role
    assert!(client
        .has_role(&accounts.outsider, &symbol_short!("deployer"))
        .is_none());
}

#[test]
fn test_get_deployed_address_without_deployment() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let salt = create_mock_salt(&e, 1);

    // Should be able to get address even without deploying
    let predicted_address = client.get_deployed_address(&salt);

    // Address should be valid
    assert_ne!(predicted_address, Address::generate(&e));
}

#[test]
fn test_get_deployed_address_consistency() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let salt = create_mock_salt(&e, 1);

    // Get predicted address multiple times
    let predicted_address1 = client.get_deployed_address(&salt);
    let predicted_address2 = client.get_deployed_address(&salt);

    // Addresses should be consistent
    assert_eq!(predicted_address1, predicted_address2);
}

#[test]
fn test_different_salts_produce_different_addresses() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let salt1 = create_mock_salt(&e, 1);
    let salt2 = create_mock_salt(&e, 2);

    let address1 = client.get_deployed_address(&salt1);
    let address2 = client.get_deployed_address(&salt2);

    // Different salts should produce different addresses
    assert_ne!(address1, address2);
}

#[test]
fn test_deployer_admin_can_grant_deployer_role() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);
    let new_deployer = Address::generate(&e);

    // Deployer admin should be able to grant deployer role
    client.grant_role(
        &accounts.deployer_admin,
        &new_deployer,
        &symbol_short!("deployer"),
    );

    // Verify the role was granted
    assert!(client
        .has_role(&new_deployer, &symbol_short!("deployer"))
        .is_some());
}

#[test]
fn test_deployer_admin_can_revoke_deployer_role() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);

    // Verify deployer1 initially has the role
    assert!(client
        .has_role(&accounts.deployer1, &symbol_short!("deployer"))
        .is_some());

    // Revoke deployer1's role
    client.revoke_role(
        &accounts.deployer_admin,
        &accounts.deployer1,
        &symbol_short!("deployer"),
    );

    // Verify the role was revoked
    assert!(client
        .has_role(&accounts.deployer1, &symbol_short!("deployer"))
        .is_none());
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_non_admin_cannot_grant_deployer_role() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);
    let new_deployer = Address::generate(&e);

    // Outsider should not be able to grant deployer role
    e.set_auths(&[]);
    client.grant_role(
        &accounts.outsider,
        &new_deployer,
        &symbol_short!("deployer"),
    );
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_non_admin_cannot_revoke_deployer_role() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);

    // Outsider should not be able to revoke deployer role
    e.set_auths(&[]);
    client.revoke_role(
        &accounts.outsider,
        &accounts.deployer1,
        &symbol_short!("deployer"),
    );
}

#[test]
fn test_admin_can_grant_deployer_role_directly() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let new_deployer = Address::generate(&e);

    // Admin should be able to grant deployer role directly
    client.grant_role(&admin, &new_deployer, &symbol_short!("deployer"));

    // Verify the role was granted
    assert!(client
        .has_role(&new_deployer, &symbol_short!("deployer"))
        .is_some());
}

#[test]
fn test_constructor_args_handling() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let _accounts = setup_roles(&e, &client, &admin);
    let salt = create_mock_salt(&e, 1);

    // Create constructor args with some values (unused but kept for documentation)
    let _arg1 = Address::generate(&e);
    let _arg2 = 42u32;
    let _constructor_args: Vec<Val> = vec![&e, _arg1.into_val(&e), _arg2.into_val(&e)];

    // Should be able to get deployed address regardless of constructor args
    let deployed_address = client.get_deployed_address(&salt);

    // Verify address is valid
    assert_ne!(deployed_address, Address::generate(&e));
}

#[test]
fn test_same_salt_produces_same_address() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let salt = create_mock_salt(&e, 1);

    // Get address multiple times with same salt
    let address1 = client.get_deployed_address(&salt);
    let address2 = client.get_deployed_address(&salt);

    // Should produce the same address
    assert_eq!(address1, address2);
}

#[test]
fn test_get_deployed_address_is_read_only() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let salt = create_mock_salt(&e, 1);

    // Should be able to call get_deployed_address without any auth
    let address1 = client.get_deployed_address(&salt);
    let address2 = client.get_deployed_address(&salt);

    // Should return the same address consistently
    assert_eq!(address1, address2);
}

#[test]
fn test_role_admin_functionality() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);

    // Verify role admin was set correctly
    assert_eq!(
        client.get_role_admin(&symbol_short!("deployer")),
        Some(symbol_short!("dep_admin"))
    );

    // Verify deployer_admin has the admin role
    assert!(client
        .has_role(&accounts.deployer_admin, &symbol_short!("dep_admin"))
        .is_some());
}

#[test]
fn test_address_prediction_before_and_after_deployment() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);
    let salt = create_mock_salt(&e, 42);

    let predicted_address = client.get_deployed_address(&salt);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);

    // Step 3: Deploy the contract with the same salt
    let constructor_args: Vec<Val> = vec![&e];

    e.set_auths(&[]);
    e.mock_all_auths_allowing_non_root_auth();

    let deployed_address = client.deploy(
        &accounts.deployer1,
        &ContractDeploymentArgs {
            wasm_hash,
            salt: salt.clone(),
            constructor_args,
        },
    );

    assert_eq!(predicted_address, deployed_address);

    let predicted_address_after = client.get_deployed_address(&salt);
    assert_eq!(predicted_address, predicted_address_after);
}

#[test]
fn test_deploy_idempotency() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);
    let accounts = setup_roles(&e, &client, &admin);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let salt = create_mock_salt(&e, 1);
    let constructor_args: Vec<Val> = vec![&e];

    let predicted_address = client.get_deployed_address(&salt);

    let deployed_address1 = client.deploy(
        &accounts.deployer1,
        &ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args: constructor_args.clone(),
        },
    );

    // Create a copy of salt for later use
    let salt_copy = create_mock_salt(&e, 1);

    // Verify first deployment returns the predicted address
    assert_eq!(deployed_address1, predicted_address);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
        let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
        let salt = create_mock_salt(&e, 1);
        let constructor_args: Vec<Val> = vec![&e];

        client.deploy(
            &accounts.deployer1,
            &ContractDeploymentArgs {
                wasm_hash,
                salt,
                constructor_args,
            },
        )
    }));

    // Verify that second deployment failed (the error type Error(Storage, ExistingValue)
    assert!(
        result.is_err(),
        "Second deployment should fail - deploy function is not idempotent"
    );

    // Verify that get_deployed_address still returns the same address (address prediction is idempotent)
    let predicted_address_after = client.get_deployed_address(&salt_copy);
    assert_eq!(predicted_address, predicted_address_after);
    assert_eq!(deployed_address1, predicted_address_after);
}

#[test]
fn test_upload_and_deploy_function_exists() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let client = create_factory_client(&e, &admin);

    let accounts = setup_roles(&e, &client, &admin);
    let salt = create_mock_salt(&e, 1);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let constructor_args: Vec<Val> = vec![&e];

    let deployed_address =
        client.upload_and_deploy(&accounts.deployer1, &wasm_bytes, &salt, &constructor_args);

    // Verify that deployment actually worked by checking the address is valid
    assert!(!deployed_address.to_string().is_empty());
}
