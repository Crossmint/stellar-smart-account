use soroban_sdk::{auth::Context, contractclient, Address, Env, Vec};

#[contractclient(name = "SmartAccountPolicyClient")]
pub trait PolicyInterface {
    fn init(env: &Env, source: Address);
    fn is_authorized(env: &Env, source: Address, contexts: &Vec<Context>) -> bool;
}
