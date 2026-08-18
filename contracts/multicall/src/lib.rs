#![no_std]

use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
use soroban_sdk::{
    contract, contractimpl, contracttype, vec, Address, Env, Error, Symbol, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

const UNREPRESENTABLE_ERROR: Error =
    Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InternalError);

#[contracttype]
#[derive(Clone, Debug)]
pub struct Call {
    pub contract: Address,
    pub function: Symbol,
    pub args: Vec<Val>,
    pub allow_failure: bool,
}

#[contract]
pub struct Multicall;

#[contractimpl]
impl Multicall {
    pub fn exec(env: Env, caller: Address, calls: Vec<Call>) -> Vec<Val> {
        caller.require_auth();
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_EXTEND_TO);

        let mut results: Vec<Val> = vec![&env];
        for call in calls.iter() {
            let Call {
                contract,
                function,
                args,
                allow_failure,
            } = call;
            let result = if allow_failure {
                match env.try_invoke_contract::<Val, Error>(&contract, &function, args) {
                    Ok(Ok(value)) => value,
                    Ok(Err(_)) => UNREPRESENTABLE_ERROR.to_val(),
                    Err(error) => error.unwrap_or(UNREPRESENTABLE_ERROR).to_val(),
                }
            } else {
                env.invoke_contract(&contract, &function, args)
            };
            results.push_back(result);
        }
        results
    }
}

#[cfg(test)]
mod test;
