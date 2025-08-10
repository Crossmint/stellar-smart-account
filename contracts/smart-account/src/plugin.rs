use soroban_sdk::{auth::Context, contractclient, Address, Env, Vec};

#[contractclient(name = "SmartAccountPluginClient")]
/// Plugin lifecycle interface for Smart Account extensions. (important-comment)
/// Failure policy:
/// - on_install: any error reverts installation with Error::PluginInitializationFailed.
/// - on_uninstall: errors do not revert; a PluginUninstallFailedEvent is emitted and uninstall continues.
/// - on_auth: invoked directly after successful authorization; a panic in the plugin will revert __check_auth.
pub trait SmartAccountPlugin {
    /// Called after a plugin is installed. (important-comment)
    fn on_install(env: &Env, source: Address);
    /// Called before a plugin is fully uninstalled. Failures are recorded via uninstall_failed event and uninstall proceeds. (important-comment)
    fn on_uninstall(env: &Env, source: Address);
    /// Called after successful authorization to observe or react to auth contexts. Panics will revert __check_auth. (important-comment)
    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>);
}
