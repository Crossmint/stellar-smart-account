#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env, Val, Vec};
use stellar_access_control::{grant_role, set_admin, AccessControl};
use stellar_access_control_macros::only_role;
use stellar_default_impl_macro::default_impl;

#[contract]
pub struct CrossmintContractFactory;

#[contractimpl]
impl CrossmintContractFactory {
    /// Construct the deployer with a given admin address.
    pub fn __constructor(env: &Env, admin: Address) {
        set_admin(env, &admin);
        grant_role(env, &admin, &admin, &symbol_short!("deployer"));
    }

    /// Deploys the contract on behalf of the `CrossmintContractFactory` contract.
    ///
    /// This has to be authorized by an address with the `deployer` role.
    /// If a contract already exists at the predicted address, returns that address.
    #[only_role(caller, "deployer")]
    pub fn deploy(
        env: Env,
        caller: Address,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        // Deploy the contract using the uploaded Wasm with given hash on behalf
        // of the current contract.
        // Note, that not deploying on behalf of the admin provides more
        // consistent address space for the deployer contracts - the deployer could
        // change or it could be a completely separate contract with complex
        // authorization rules, but all the contracts will still be deployed
        // by the same `CrossmintContractFactory` contract address.
        let deployed_address = env
            .deployer()
            .with_address(env.current_contract_address(), salt)
            .deploy_v2(wasm_hash, constructor_args);

        deployed_address
    }

    pub fn get_deployed_address(env: Env, salt: BytesN<32>) -> Address {
        env.deployer()
            .with_address(env.current_contract_address(), salt)
            .deployed_address()
    }
}

#[default_impl]
#[contractimpl]
impl AccessControl for CrossmintContractFactory {}

mod test;
