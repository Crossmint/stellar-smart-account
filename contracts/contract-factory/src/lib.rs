#![no_std]
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Symbol, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

#[contract]
pub struct ContractFactory;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeploymentArgs {
    wasm_hash: BytesN<32>,
    salt: BytesN<32>,
    constructor_args: Vec<Val>,
}

#[contractevent(topics = ["DEPLOYED"], data_format = "single-value")]
pub struct ContractDeployedEvent {
    pub contract_id: Address,
}

#[contractimpl]
impl ContractFactory {
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_EXTEND_TO);
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

    fn deploy_and_emit(
        env: &Env,
        derived_salt: BytesN<32>,
        wasm_hash: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let contract_id = env
            .deployer()
            .with_current_contract(derived_salt)
            .deploy_v2(wasm_hash, constructor_args);

        ContractDeployedEvent {
            contract_id: contract_id.clone(),
        }
        .publish(env);
        contract_id
    }

    /// Deploys a contract on behalf of the `ContractFactory` contract.
    pub fn deploy(env: &Env, deployment_args: ContractDeploymentArgs) -> Address {
        Self::extend_instance_ttl(env);
        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        Self::deploy_and_emit(env, derived_salt, wasm_hash, constructor_args)
    }

    /// Deploys a contract on behalf of the `ContractFactory` contract.
    /// If the contract is already deployed at the deterministic address, returns it.
    pub fn deploy_idempotent(env: &Env, deployment_args: ContractDeploymentArgs) -> Address {
        Self::extend_instance_ttl(env);
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
        Self::deploy_and_emit(env, derived_salt, wasm_hash, constructor_args)
    }

    /// Uploads the contract WASM and deploys it on behalf of the `ContractFactory` contract.
    pub fn upload_and_deploy(
        env: &Env,
        wasm_bytes: Bytes,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        Self::extend_instance_ttl(env);
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);
        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        Self::deploy_and_emit(env, derived_salt, wasm_hash, constructor_args)
    }

    pub fn get_deployed_address(
        env: &Env,
        salt: BytesN<32>,
        wasm_hash: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        Self::extend_instance_ttl(env);
        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        env.deployer()
            .with_current_contract(derived_salt)
            .deployed_address()
    }
}

mod test;

#[cfg(test)]
mod test_constants;
