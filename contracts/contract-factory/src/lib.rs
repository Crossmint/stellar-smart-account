#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, vec, xdr::ToXdr, Address,
    Bytes, BytesN, Env, Symbol, Val, Vec,
};

const DEPLOYED_CONTRACT: Symbol = symbol_short!("DEPLOYED");

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

#[contract]
pub struct ContractFactory;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FactoryError {
    DeploymentFailed = 1,
    InnerCallFailed = 2,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeploymentArgs {
    pub wasm_hash: BytesN<32>,
    pub salt: BytesN<32>,
    pub constructor_args: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCall {
    pub target: Address,
    pub function: Symbol,
    pub args: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployAndCallResult {
    pub address: Address,
    pub results: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeployedEvent {
    contract_id: Address,
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

    fn predict_and_check_deployed(
        env: &Env,
        deployment_args: &ContractDeploymentArgs,
    ) -> (Address, bool) {
        let tentative_contract_id = Self::get_deployed_address(
            env,
            deployment_args.salt.clone(),
            deployment_args.wasm_hash.clone(),
            deployment_args.constructor_args.clone(),
        );
        let is_deployed = env
            .try_invoke_contract::<bool, soroban_sdk::Error>(
                &tentative_contract_id,
                &Symbol::new(env, "is_deployed"),
                Vec::new(env),
            )
            .is_ok();
        (tentative_contract_id, is_deployed)
    }

    /// Deploys a contract on behalf of the `ContractFactory` contract.
    pub fn deploy(
        env: &Env,
        deployment_args: ContractDeploymentArgs,
    ) -> Result<Address, FactoryError> {
        Self::extend_instance_ttl(env);
        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        Ok(Self::deploy_and_emit(
            env,
            derived_salt,
            wasm_hash,
            constructor_args,
        ))
    }

    /// Deploys a contract on behalf of the `ContractFactory` contract.
    /// If the contract is already deployed at the deterministic address, returns it.
    pub fn deploy_idempotent(
        env: &Env,
        deployment_args: ContractDeploymentArgs,
    ) -> Result<Address, FactoryError> {
        Self::extend_instance_ttl(env);
        let (tentative_contract_id, is_deployed) =
            Self::predict_and_check_deployed(env, &deployment_args);

        if is_deployed {
            return Ok(tentative_contract_id);
        }

        let ContractDeploymentArgs {
            wasm_hash,
            salt,
            constructor_args,
        } = deployment_args;

        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        Ok(Self::deploy_and_emit(
            env,
            derived_salt,
            wasm_hash,
            constructor_args,
        ))
    }

    /// Idempotently deploys a contract and then dispatches a sequence of inner
    /// contract calls, returning the deployed address alongside the raw return
    /// value of each inner call.
    ///
    /// If any inner call reverts, `FactoryError::InnerCallFailed` is returned
    /// and the whole transaction is rolled back by the host.
    pub fn deploy_idempotent_and_call(
        env: &Env,
        deployment_args: ContractDeploymentArgs,
        calls: Vec<ContractCall>,
    ) -> Result<DeployAndCallResult, FactoryError> {
        Self::extend_instance_ttl(env);

        let (tentative_contract_id, is_deployed) =
            Self::predict_and_check_deployed(env, &deployment_args);

        let address = if is_deployed {
            tentative_contract_id
        } else {
            let ContractDeploymentArgs {
                wasm_hash,
                salt,
                constructor_args,
            } = deployment_args;
            let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
            Self::deploy_and_emit(env, derived_salt, wasm_hash, constructor_args)
        };

        let mut results: Vec<Val> = Vec::new(env);
        for call in calls.iter() {
            let result = env
                .try_invoke_contract::<Val, soroban_sdk::Error>(
                    &call.target,
                    &call.function,
                    call.args.clone(),
                )
                .map_err(|_| FactoryError::InnerCallFailed)?
                .map_err(|_| FactoryError::InnerCallFailed)?;
            results.push_back(result);
        }

        Ok(DeployAndCallResult { address, results })
    }

    /// Uploads the contract WASM and deploys it on behalf of the `ContractFactory` contract.
    pub fn upload_and_deploy(
        env: &Env,
        wasm_bytes: Bytes,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Result<Address, FactoryError> {
        Self::extend_instance_ttl(env);
        let wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);
        let derived_salt = Self::derive_salt(env, salt, &wasm_hash, &constructor_args);
        Ok(Self::deploy_and_emit(
            env,
            derived_salt,
            wasm_hash,
            constructor_args,
        ))
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
