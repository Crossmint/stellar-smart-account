#![cfg(test)]

use super::*;
use soroban_sdk::{contract, contractimpl, log, panic_with_error, Env};

#[contract]
pub struct ExampleContract;

#[contractimpl]
impl ExampleContract {
    pub fn __constructor(env: &Env) {
        let _ = Self::initialize(env).map_err(|e| panic_with_error!(env, e));
    }

    pub fn only_initialized_fn(env: &Env) {
        only_initialized!(env);
        log!(env, "I am initialized");
    }

    pub fn only_not_initialized_fn(env: &Env) {
        only_not_initialized!(env);
        log!(env, "I am not initialized");
    }
}

impl Initializable for ExampleContract {}

#[test]
fn test_should_deploy() {
    let env = Env::default();
    let contract_id = env.register(ExampleContract, ());
    let _client = ExampleContractClient::new(&env, &contract_id);
}

#[test]
fn test_should_deploy_and_invoke_only_initialized_fn() {
    let env = Env::default();
    let contract_id = env.register(ExampleContract, ());
    let client = ExampleContractClient::new(&env, &contract_id);
    client.only_initialized_fn();
}

#[test]
#[should_panic(expected = "Error(Contract, #0)")]
fn test_should_deploy_and_fail_to_invoke_only_not_initialized_fn() {
    let env = Env::default();
    let contract_id = env.register(ExampleContract, ());
    let client = ExampleContractClient::new(&env, &contract_id);
    client.only_not_initialized_fn();
}
