use soroban_sdk::{Address, Env, Vec};

use crate::auth::signer::{Signer, SignerKey};
use crate::error::Error;

/// Public API of the Smart Account contract.
///
/// Provides initialization, signer management, and plugin lifecycle operations.
pub trait SmartAccountInterface {
    /// Initializes the contract with the given signers and plugins.
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>);
    /// Adds a new signer to the account.
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    /// Updates an existing signer configuration.
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    /// Revokes a signer by key.
    fn revoke_signer(env: &Env, signer: SignerKey) -> Result<(), Error>;
    /// Gets a signer by key.
    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, Error>;
    /// Checks if a signer exists.
    fn has_signer(env: &Env, signer_key: SignerKey) -> Result<bool, Error>;
    /// Installs a plugin and invokes its initialization hook.
    fn install_plugin(env: &Env, plugin: Address) -> Result<(), Error>;
    /// Uninstalls a plugin and invokes its uninstall hook. Emits uninstall_failed on hook error.
    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), Error>;
    /// Checks if a plugin is installed.
    fn is_plugin_installed(env: &Env, plugin: Address) -> bool;
}
