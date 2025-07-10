#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Val, Vec};
use stellar_access_control::{grant_role, set_admin, AccessControl};
use stellar_access_control_macros::only_role;
use stellar_default_impl_macro::default_impl;

///
/// address generation for predictable contract locations.
///
#[contract]
pub struct CrossmintContractFactory;

#[contractimpl]
impl CrossmintContractFactory {
    ///
    /// address as both the system administrator and granting it the `deployer` role.
    ///
    ///
    ///
    ///
    pub fn __constructor(env: &Env, admin: Address) {
        set_admin(env, &admin);
        grant_role(env, &admin, &admin, &symbol_short!("deployer"));
    }

    /// Deploys a contract using pre-uploaded WASM bytecode.
    ///
    /// Deploys a smart contract on behalf of the factory using previously uploaded WASM.
    ///
    ///
    ///
    ///
    /// The address of the newly deployed contract.
    ///
    ///
    ///
    ///
    /// address is deterministic based on:
    ///
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
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, constructor_args);

        deployed_address
    }

    /// Uploads WASM bytecode and deploys the contract in a single operation.
    ///
    ///
    ///
    ///
    ///
    /// The address of the newly deployed contract.
    ///
    ///
    ///
    ///
    /// the WASM, but may be more expensive as it includes the upload operation.
    #[only_role(caller, "deployer")]
    pub fn upload_and_deploy(
        env: Env,
        caller: Address,
        wasm_bytes: Bytes,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);

        // Deploy the contract using the uploaded WASM hash on behalf
        // of the current contract.
        let deployed_address = env
            .deployer()
            .with_address(env.current_contract_address(), salt)
            .deploy_v2(wasm_hash, constructor_args);

        deployed_address
    }

    ///
    ///
    ///
    ///
    ///
    /// The address where a contract would be deployed using the given salt.
    ///
    ///
    ///
    ///
    pub fn get_deployed_address(env: Env, salt: BytesN<32>) -> Address {
        env.deployer()
            .with_current_contract(salt)
            .deployed_address()
    }
}

///
///
#[default_impl]
#[contractimpl]
impl AccessControl for CrossmintContractFactory {}

mod test;

#[cfg(test)]
mod test_constants;
