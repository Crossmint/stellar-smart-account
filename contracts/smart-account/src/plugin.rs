use soroban_sdk::{auth::Context, contractclient, Address, Env, Vec};

#[contractclient(name = "SmartAccountPluginClient")]
/// Plugin lifecycle interface for Smart Account extensions.
pub trait SmartAccountPlugin {
    /// Called after a plugin is installed.
    fn on_install(env: &Env, source: Address);
    /// Called before a plugin is fully uninstalled. Failures are recorded via uninstall_failed event.
    fn on_uninstall(env: &Env, source: Address);
    /// Called after successful authorization to observe or react to auth contexts.
    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>);
}
