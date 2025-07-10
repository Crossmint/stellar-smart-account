#![cfg(test)]

use super::*;
use soroban_sdk::{
    auth::Context,
    map,
    testutils::Address as _,
    vec, Address, Bytes, BytesN, Env, Vec,
};
use types::{Signature, SignerKey, Signatures};

#[test]
fn test_check_auth_always_succeeds() {
    let env = Env::default();
    
    let data = Bytes::from_slice(&env, &[0u8; 32]);
    let signature_payload = env.crypto().sha256(&data);
    let signatures = Signatures(map![&env]);
    let auth_contexts: Vec<Context> = vec![&env];

    let result = Contract::__check_auth(env, signature_payload, signatures, auth_contexts);
    assert!(result.is_ok());
}

#[test]
fn test_check_auth_with_ed25519_signature() {
    let env = Env::default();
    
    let data = Bytes::from_slice(&env, &[1u8; 32]);
    let signature_payload = env.crypto().sha256(&data);
    let ed25519_key = SignerKey::Ed25519(BytesN::from_array(&env, &[1u8; 32]));
    let ed25519_sig = Signature::Ed25519(BytesN::from_array(&env, &[2u8; 64]));
    let signatures = Signatures(map![&env, (ed25519_key, ed25519_sig)]);
    let auth_contexts: Vec<Context> = vec![&env];

    let result = Contract::__check_auth(env, signature_payload, signatures, auth_contexts);
    assert!(result.is_ok());
}

#[test]
fn test_check_auth_with_policy_signature() {
    let env = Env::default();
    
    let data = Bytes::from_slice(&env, &[2u8; 32]);
    let signature_payload = env.crypto().sha256(&data);
    
    let policy_key = SignerKey::Policy(Address::generate(&env));
    let policy_sig = Signature::Policy;
    
    let signatures = Signatures(map![&env, (policy_key, policy_sig)]);
    let auth_contexts: Vec<Context> = vec![&env];

    let result = Contract::__check_auth(env, signature_payload, signatures, auth_contexts);
    assert!(result.is_ok());
}

#[test]
fn test_smart_account_contract_registration() {
    let env = Env::default();
    let contract_address = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_address);
    
    assert_eq!(contract_address, client.address);
}
