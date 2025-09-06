use soroban_sdk::contractclient;
use soroban_sdk::{Address, Env, Vec};

use crate::policy::Signer;
use crate::policy::SignerKey;
use crate::policy::SmartAccountError;

/// Public API of the Smart Account contract.
///
/// Provides initialization, signer management, and plugin lifecycle operations.
#[contractclient(name = "SmartAccountClient")]
pub trait SmartAccountInterface {
    /// Initializes the contract with the given signers and plugins.
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>);
    /// Adds a new signer to the account.
    fn add_signer(env: &Env, signer: Signer) -> Result<(), SmartAccountError>;
    /// Updates an existing signer configuration.
    fn update_signer(env: &Env, signer: Signer) -> Result<(), SmartAccountError>;
    /// Revokes a signer by key.
    fn revoke_signer(env: &Env, signer: SignerKey) -> Result<(), SmartAccountError>;
    /// Gets a signer by key.
    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, SmartAccountError>;
    /// Checks if a signer exists.
    fn has_signer(env: &Env, signer_key: SignerKey) -> Result<bool, SmartAccountError>;
    /// Installs a plugin and invokes its initialization hook.
    fn install_plugin(env: &Env, plugin: Address) -> Result<(), SmartAccountError>;
    /// Uninstalls a plugin and invokes its uninstall hook. Emits uninstall_failed on hook error.
    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), SmartAccountError>;
    /// Checks if a plugin is installed.
    fn is_plugin_installed(env: &Env, plugin: Address) -> bool;
}
