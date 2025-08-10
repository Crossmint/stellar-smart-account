#![cfg(test)]

use super::*;
use soroban_sdk::{contract, contractimpl, Address, Env, String as SorobanString, Symbol};

#[contract]
pub struct StorageTestContract;

#[contractimpl]
impl StorageTestContract {
    pub fn store_and_check(env: Env, key: Symbol, value: SorobanString) -> bool {
        let storage = Storage::default();
        storage.store(&env, &key, &value).is_ok()
    }

    pub fn store_persistent_and_check(env: Env, key: Symbol, value: SorobanString) -> bool {
        let storage = Storage {
            storage_type: StorageType::Persistent,
        };
        storage.store(&env, &key, &value).is_ok()
    }

    pub fn get_value(env: Env, key: Symbol) -> Option<SorobanString> {
        let storage = Storage::default();
        storage.get(&env, &key)
    }

    pub fn get_persistent_value(env: Env, key: Symbol) -> Option<SorobanString> {
        let storage = Storage {
            storage_type: StorageType::Persistent,
        };
        storage.get(&env, &key)
    }

    pub fn update_and_check(env: Env, key: Symbol, value: SorobanString) -> bool {
        let storage = Storage::default();
        storage.update(&env, &key, &value).is_ok()
    }

    pub fn delete_and_check(env: Env, key: Symbol) -> bool {
        let storage = Storage::default();
        storage.delete(&env, &key).is_ok()
    }

    pub fn has_key(env: Env, key: Symbol) -> bool {
        let storage = Storage::default();
        storage.has(&env, &key)
    }

    pub fn has_persistent_key(env: Env, key: Symbol) -> bool {
        let storage = Storage {
            storage_type: StorageType::Persistent,
        };
        storage.has(&env, &key)
    }

    pub fn try_duplicate_store(env: Env, key: Symbol, value: SorobanString) -> bool {
        let storage = Storage::default();
        // First store should succeed
        let _ = storage.store(&env, &key, &value);
        // Second store should fail
        storage.store(&env, &key, &value).is_err()
    }

    pub fn try_update_nonexistent(env: Env, key: Symbol, value: SorobanString) -> bool {
        let storage = Storage::default();
        storage.update(&env, &key, &value).is_err()
    }

    pub fn try_delete_nonexistent(env: Env, key: Symbol) -> bool {
        let storage = Storage::default();
        storage.delete(&env, &key).is_err()
    }
}

fn create_test_env() -> (Env, Address, StorageTestContractClient<'static>) {
    let env = Env::default();
    let contract_address = env.register(StorageTestContract, ());
    let client = StorageTestContractClient::new(&env, &contract_address);
    (env, contract_address, client)
}

#[test]
fn test_default_storage_type() {
    let storage = Storage::default();
    assert!(matches!(storage.storage_type, StorageType::Instance));
}

#[test]
fn test_instance_storage_store_and_get() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let value = SorobanString::from_str(&env, "test_value");

    // Test store
    let store_result = client.store_and_check(&key, &value);
    assert!(store_result);

    // Test get
    let retrieved_value = client.get_value(&key);
    assert!(retrieved_value.is_some());
    assert_eq!(retrieved_value.unwrap(), value);
}

#[test]
fn test_persistent_storage_store_and_get() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let value = SorobanString::from_str(&env, "test_value");

    // Test store
    let store_result = client.store_persistent_and_check(&key, &value);
    assert!(store_result);

    // Test get
    let retrieved_value = client.get_persistent_value(&key);
    assert!(retrieved_value.is_some());
    assert_eq!(retrieved_value.unwrap(), value);
}

#[test]
fn test_store_already_exists_error() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let value = SorobanString::from_str(&env, "test_value");

    // This should return true because the second store fails
    let duplicate_store_fails = client.try_duplicate_store(&key, &value);
    assert!(duplicate_store_fails);
}

#[test]
fn test_update_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let initial_value = SorobanString::from_str(&env, "initial");
    let updated_value = SorobanString::from_str(&env, "updated");

    // Store initial value
    assert!(client.store_and_check(&key, &initial_value));

    // Update the value
    let update_result = client.update_and_check(&key, &updated_value);
    assert!(update_result);

    // Verify the value was updated
    let retrieved_value = client.get_value(&key);
    assert!(retrieved_value.is_some());
    assert_eq!(retrieved_value.unwrap(), updated_value);
}

#[test]
fn test_update_non_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "non_existing_key");
    let value = SorobanString::from_str(&env, "value");

    // Update should fail for non-existing key
    let update_fails = client.try_update_nonexistent(&key, &value);
    assert!(update_fails);
}

#[test]
fn test_delete_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let value = SorobanString::from_str(&env, "test_value");

    // Store a value
    assert!(client.store_and_check(&key, &value));

    // Verify it exists
    assert!(client.has_key(&key));

    // Delete the key
    let delete_result = client.delete_and_check(&key);
    assert!(delete_result);

    // Verify it no longer exists
    assert!(!client.has_key(&key));

    // Verify get returns None
    let retrieved_value = client.get_value(&key);
    assert!(retrieved_value.is_none());
}

#[test]
fn test_delete_non_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "non_existing_key");

    // Delete should fail for non-existing key
    let delete_fails = client.try_delete_nonexistent(&key);
    assert!(delete_fails);
}

#[test]
fn test_has_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let value = SorobanString::from_str(&env, "test_value");

    // Initially key should not exist
    assert!(!client.has_key(&key));

    // Store a value
    assert!(client.store_and_check(&key, &value));

    // Now key should exist
    assert!(client.has_key(&key));
}

#[test]
fn test_has_non_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "non_existing_key");

    // Key should not exist
    assert!(!client.has_key(&key));
}

#[test]
fn test_get_non_existing_key() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "non_existing_key");

    // Get should return None
    let result = client.get_value(&key);
    assert!(result.is_none());
}

#[test]
fn test_persistent_vs_instance_storage_isolation() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "test_key");
    let instance_value = SorobanString::from_str(&env, "instance_value");
    let persistent_value = SorobanString::from_str(&env, "persistent_value");

    // Store different values in each storage type
    assert!(client.store_and_check(&key, &instance_value));
    assert!(client.store_persistent_and_check(&key, &persistent_value));

    // Verify they are isolated
    let retrieved_instance = client.get_value(&key);
    let retrieved_persistent = client.get_persistent_value(&key);

    assert_eq!(retrieved_instance.unwrap(), instance_value);
    assert_eq!(retrieved_persistent.unwrap(), persistent_value);
}

#[test]
fn test_complete_workflow() {
    let (env, _contract_address, client) = create_test_env();

    let key = Symbol::new(&env, "workflow_key");
    let initial_value = SorobanString::from_str(&env, "initial");
    let updated_value = SorobanString::from_str(&env, "updated");

    // 1. Key should not exist initially
    assert!(!client.has_key(&key));
    assert!(client.get_value(&key).is_none());

    // 2. Store initial value
    assert!(client.store_and_check(&key, &initial_value));
    assert!(client.has_key(&key));
    assert_eq!(client.get_value(&key).unwrap(), initial_value);

    // 3. Update the value
    assert!(client.update_and_check(&key, &updated_value));
    assert!(client.has_key(&key));
    assert_eq!(client.get_value(&key).unwrap(), updated_value);

    // 4. Delete the key
    assert!(client.delete_and_check(&key));
    assert!(!client.has_key(&key));
    assert!(client.get_value(&key).is_none());
}
