#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, BytesN, Env, Symbol,
    Val, Vec,
};
use stellar_access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_access_control_macros::only_role;
use stellar_default_impl_macro::default_impl;

const DEPLOYED_CONTRACT: Symbol = symbol_short!("DEPLOYED");

#[contract]
pub struct ContractFactory;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCall {
    contract_id: Address,
    func: Symbol,
    args: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeploymentArgs {
    wasm_hash: BytesN<32>,
    salt: BytesN<32>,
    constructor_args: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeployedEvent {
    contract_id: Address,
}

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
    // #[only_role(caller, "deployer")]
    pub fn deploy(env: &Env, caller: Address, deployment_args: ContractDeploymentArgs) -> Address {
        // Deploy the contract using the uploaded Wasm with given hash on behalf
        // of the current contract.
        // Note, that not deploying on behalf of the admin provides more
        // consistent address space for the deployer contracts - the deployer could
        // change or it could be a completely separate contract with complex
        // authorization rules, but all the contracts will still be deployed
        // by the same `ContractFactory` contract address.

        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let contract_id = env
            .deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, constructor_args);

        env.events().publish(
            vec![env, DEPLOYED_CONTRACT],
            vec![
                env,
                ContractDeployedEvent {
                    contract_id: contract_id.clone(),
                },
            ],
        );
        contract_id
    }

    /// Deploys a smart account on behalf of the `ContractFactory` contract.
    /// and calls a function that could require auth for that deployed account.
    ///
    /// This has to be authorized by an address with the `deployer` role and by
    /// the account own authorization
    pub fn deploy_account_and_invoke(
        env: &Env,
        caller: Address,
        deployment_args: ContractDeploymentArgs,
        calls: Vec<ContractCall>,
    ) -> Val {
        // Requires auth for the deployer
        let contract_id = Self::deploy(env, caller, deployment_args);

        contract_id.require_auth();

        let mut results = Vec::<Val>::new(env);
        for call in calls {
            let ContractCall {
                contract_id,
                func,
                args,
            } = call;
            results.push_back(env.invoke_contract(&contract_id, &func, args));
        }
        results.into()
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
}

#[default_impl]
#[contractimpl]
impl AccessControl for ContractFactory {}

mod test;

#[cfg(test)]
mod test_constants;
