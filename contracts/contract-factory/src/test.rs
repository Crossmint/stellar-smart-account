#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::Address as _, vec, Address, BytesN, Env, IntoVal, Val, Vec};

use crate::test_constants::SMART_ACCOUNT_WASM;
use crate::{ContractDeploymentArgs, ContractFactory, ContractFactoryClient};

fn create_factory_client<'a>(e: &Env) -> ContractFactoryClient<'a> {
    let address = e.register(ContractFactory, ());
    ContractFactoryClient::new(e, &address)
}

// Helper function to create a mock salt
fn create_mock_salt(e: &Env, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = value; // Make it unique
    BytesN::from_array(e, &bytes)
}

#[test]
fn test_get_deployed_address_without_deployment() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);
    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let constructor_args: Vec<Val> = vec![&e];

    let predicted_address = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    assert_ne!(predicted_address, Address::generate(&e));
}

#[test]
fn test_different_salts_produce_different_addresses() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt1 = create_mock_salt(&e, 1);
    let salt2 = create_mock_salt(&e, 2);
    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let constructor_args: Vec<Val> = vec![&e];

    let address1 = client.get_deployed_address(&salt1, &wasm_hash, &constructor_args);
    let address2 = client.get_deployed_address(&salt2, &wasm_hash, &constructor_args);

    assert_ne!(address1, address2);
}

#[test]
fn test_constructor_args_handling() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let arg1 = Address::generate(&e);
    let arg2 = 42u32;
    let constructor_args: Vec<Val> = vec![&e, arg1.into_val(&e), arg2.into_val(&e)];

    let deployed_address = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    assert_ne!(deployed_address, Address::generate(&e));
}

#[test]
fn test_same_salt_produces_same_address() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);
    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let constructor_args: Vec<Val> = vec![&e];

    let address1 = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);
    let address2 = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    assert_eq!(address1, address2);
}

#[test]
fn test_address_prediction_before_and_after_deployment() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 42);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let constructor_args: Vec<Val> = vec![&e];

    let predicted_address = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    let deployed_address = client.deploy(&ContractDeploymentArgs {
        wasm_hash: wasm_hash.clone(),
        salt: salt.clone(),
        constructor_args: constructor_args.clone(),
    });

    assert_eq!(predicted_address, deployed_address);

    let predicted_address_after = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);
    assert_eq!(predicted_address, predicted_address_after);
}

#[test]
fn test_deploy_idempotency() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let salt = create_mock_salt(&e, 1);
    let constructor_args: Vec<Val> = vec![&e];

    let predicted_address = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    let deployed_address1 = client.deploy(&ContractDeploymentArgs {
        wasm_hash: wasm_hash.clone(),
        salt,
        constructor_args: constructor_args.clone(),
    });

    let salt_copy = create_mock_salt(&e, 1);

    assert_eq!(deployed_address1, predicted_address);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
        let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
        let salt = create_mock_salt(&e, 1);
        let constructor_args: Vec<Val> = vec![&e];

        client.deploy(&ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        })
    }));

    assert!(
        result.is_err(),
        "Second deployment should fail - deploy function is not idempotent"
    );

    let predicted_address_after =
        client.get_deployed_address(&salt_copy, &wasm_hash, &constructor_args);
    assert_eq!(predicted_address, predicted_address_after);
    assert_eq!(deployed_address1, predicted_address_after);
}

#[test]
fn test_upload_and_deploy() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let constructor_args: Vec<Val> = vec![&e];

    let deployed_address = client.upload_and_deploy(&wasm_bytes, &salt, &constructor_args);

    // Verify that deployment actually worked by checking the address is valid
    assert!(!deployed_address.to_string().is_empty());
}
