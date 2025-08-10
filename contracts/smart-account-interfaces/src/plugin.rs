use soroban_sdk::{auth::Context, contractclient, Address, Env, Vec};

#[contractclient(name = "SmartAccountPluginClient")]
pub trait SmartAccountPlugin {
    fn on_install(env: &Env, source: Address);
    fn on_uninstall(env: &Env, source: Address);
    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>);
}
