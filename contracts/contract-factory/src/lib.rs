#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, xdr::ToXdr, Address, Bytes, BytesN,
    Env, Symbol, Val, Vec,
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

    fn derive_salt(
        env: &Env,
        input_salt: BytesN<32>,
        wasm_hash: &BytesN<32>,
        constructor_args: &Vec<Val>,
    ) -> BytesN<32> {
        let mut bytes = Bytes::new(env);
        bytes.append(&input_salt.into());
        bytes.append(&wasm_hash.clone().into());

        for arg in constructor_args.iter() {
            let arg_bytes = arg.to_xdr(env);
            bytes.append(&arg_bytes);
        }

        env.crypto().sha256(&bytes).into()
    }

    /// Deploys the contract on behalf of the `ContractFactory` contract.
    ///
    /// This has to be authorized by an address with the `deployer` role.
    #[only_role(caller, "deployer")]
    pub fn deploy(env: &Env, caller: Address, deployment_args: ContractDeploymentArgs) -> Address {
        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);

        let contract_id = env
            .deployer()
            .with_current_contract(derived_salt)
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

    /// Deploys the contract on behalf of the `ContractFactory` contract.
    ///
    /// This has to be authorized by an address with the `deployer` role.
    #[only_role(caller, "deployer")]
    pub fn deploy_idempotent(
        env: &Env,
        caller: Address,
        deployment_args: ContractDeploymentArgs,
    ) -> Address {
        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let tentative_contract_id = Self::get_deployed_address(
            env,
            salt.clone(),
            wasm_hash.clone(),
            constructor_args.clone(),
        );
        let is_deployed = env
            .try_invoke_contract::<bool, soroban_sdk::Error>(
                &tentative_contract_id,
                &Symbol::new(env, "is_deployed"),
                Vec::new(env),
            )
            .is_ok();

        if is_deployed {
            return tentative_contract_id;
        }

        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);

        let contract_id = env
            .deployer()
            .with_current_contract(derived_salt)
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

        let derived_salt = Self::derive_salt(&env, salt, &wasm_hash, &constructor_args);

        env.deployer()
            .with_address(env.current_contract_address(), derived_salt)
            .deploy_v2(wasm_hash, constructor_args)
    }

    pub fn get_deployed_address(
        env: &Env,
        salt: BytesN<32>,
        wasm_hash: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        env.deployer()
            .with_current_contract(derived_salt)
            .deployed_address()
    }
}

#[default_impl]
#[contractimpl]
impl AccessControl for ContractFactory {}

mod test;

#[cfg(test)]
mod test_constants;
