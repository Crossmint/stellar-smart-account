#![no_std]
use soroban_sdk::{auth::Context, contract, contractimpl, symbol_short, Address, Env, Symbol, Vec};

use smart_account::SmartAccountPolicy;

const TOKEN_SYMBOL: Symbol = symbol_short!("TOKEN");

#[contract]
pub struct SACTokenPolicy;

#[contractimpl]
impl SACTokenPolicy {
    fn __constructor(env: &Env, token_address: Address) {
        env.storage().instance().set(&TOKEN_SYMBOL, &token_address);
    }
}

#[contractimpl]
impl SmartAccountPolicy for SACTokenPolicy {
    fn is_authorized(env: &Env, _source: Address, _contexts: Vec<Context>) -> bool {
        true
    }

    fn on_add(env: &Env, source: Address) {
        source.require_auth();
        env.storage().instance().set(&source, &0);
    }

    fn on_revoke(env: &Env, source: Address) {}
}
