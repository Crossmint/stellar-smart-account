#![no_std]
use smart_account_interfaces::SmartAccountPolicy;
use soroban_sdk::{auth::Context, contract, contractimpl, symbol_short, Address, Env, Symbol, Vec};

const CONTRACTS_SYMBOL: Symbol = symbol_short!("CONTRACTS");

#[contract]
pub struct DenyListPolicy;

#[contractimpl]
impl DenyListPolicy {
    pub fn __constructor(env: &Env, denied_contracts: Vec<Address>) {
        env.storage()
            .instance()
            .set(&CONTRACTS_SYMBOL, &denied_contracts);
    }
}

#[contractimpl]
impl SmartAccountPolicy for DenyListPolicy {
    fn is_authorized(env: &Env, _source: Address, contexts: Vec<Context>) -> bool {
        let denied_contracts: Vec<Address> =
            env.storage().instance().get(&CONTRACTS_SYMBOL).unwrap();
        contexts.iter().all(|context| match context {
            Context::Contract(contract) => {
                if denied_contracts.contains(&contract.contract) {
                    return false;
                }
                true
            }
            _ => true,
        })
    }

    fn on_add(env: &Env, source: Address) {
        source.require_auth();
        env.storage().instance().set(&source, &0);
    }

    fn on_revoke(_env: &Env, _source: Address) {}
}
