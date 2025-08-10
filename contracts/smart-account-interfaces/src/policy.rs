use soroban_sdk::prelude::*;
use soroban_sdk::{auth::Context, contractclient, Address, Env};

#[contractclient(name = "SmartAccountPolicyClient")]
pub trait SmartAccountPolicy {
    fn on_add(env: &Env, source: Address);
    fn on_revoke(env: &Env, source: Address);
    fn is_authorized(env: &Env, source: Address, contexts: Vec<Context>) -> bool;
}
