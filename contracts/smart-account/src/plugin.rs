use soroban_sdk::{auth::Context, contractclient, contracttype, Address, Env, Vec};

#[contractclient(name = "SmartAccountPluginClient")]
pub trait SmartAccountPlugin {
    fn on_install(env: &Env, source: Address);
    fn on_uninstall(env: &Env, source: Address);
    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>);
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PluginMetadata {
    pub address: Address,
    pub version: u32,
    pub dependencies: Vec<Address>,
    pub installed_at: u64,
}
