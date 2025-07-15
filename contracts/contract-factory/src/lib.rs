#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Val, Vec};
use stellar_access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_access_control_macros::only_role;
use stellar_default_impl_macro::default_impl;

pub trait DeploymentHealthCheck {
    fn is_deployed(env: Env) -> Result<bool, soroban_sdk::Error>;
}

#[contract]
pub struct ContractFactory;

#[contractimpl]
impl ContractFactory {
    /// Construct the deployer with a given admin address.
    pub fn __constructor(env: &Env, admin: Address) {
        set_admin(env, &admin);
        grant_role_no_auth(env, &admin, &admin, &symbol_short!("deployer"));
    }

    /// Deploys the contract on behalf of the `ContractFactory` contract.
    ///
    /// This has to be authorized by an address with the `deployer` role.
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
        // by the same `ContractFactory` contract address.

        env.deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, constructor_args)
    }

    /// Uploads the contract WASM and deploys it on behalf of the `ContractFactory` contract.
    ///
    /// using that hash. This has to be authorized by an address with the `deployer` role.
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

        env.deployer()
            .with_address(env.current_contract_address(), salt)
            .deploy_v2(wasm_hash, constructor_args)
    }

    pub fn get_deployed_address(env: Env, salt: BytesN<32>) -> Address {
        env.deployer()
            .with_current_contract(salt)
            .deployed_address()
    }

    /// Deploys the contract idempotently - returns existing address if already deployed,
    /// otherwise deploys a new contract.
    #[only_role(caller, "deployer")]
    pub fn deploy_idempotent(
        env: Env,
        caller: Address,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let _predicted_address = env
            .deployer()
            .with_current_contract(salt.clone())
            .deployed_address();

        
        env.deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, constructor_args)
    }

    /// Uploads and deploys the contract idempotently.
    #[only_role(caller, "deployer")]
    pub fn upload_and_deploy_idempotent(
        env: Env,
        caller: Address,
        wasm_bytes: Bytes,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);

        Self::deploy_idempotent(env, caller, wasm_hash, salt, constructor_args)
    }
}

#[default_impl]
#[contractimpl]
impl AccessControl for ContractFactory {}

mod test;

#[cfg(test)]
mod test_constants;
