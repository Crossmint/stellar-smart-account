use soroban_sdk::{Address, Env, Vec};

use crate::auth::signer::{Signer, SignerKey};
use crate::error::Error;

/// Smart Account Interface
pub trait SmartAccountInterface {
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>);

    // Admin operations

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error>;

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error>;

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error>;

    // Plugin operations

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn install_plugin(env: &Env, plugin: Address) -> Result<(), Error>;

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    ///
    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), Error>;

    // Batch operations

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn add_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error>;

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn update_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error>;

    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    ///
    fn revoke_signers_batch(env: &Env, signer_keys: Vec<SignerKey>) -> Result<(), Error>;
}
