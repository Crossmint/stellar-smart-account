use soroban_sdk::{Address, Env, Vec};

use crate::auth::signer::{Signer, SignerKey};
use crate::error::Error;

/// Smart Account Interface
pub trait SmartAccountInterface {
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>);

    // Admin operations

    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error>;

    // Plugin operations
    fn install_plugin(env: &Env, plugin: Address) -> Result<(), Error>;
    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), Error>;

    // Batch operations
    fn add_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error>;
    fn update_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error>;
    fn revoke_signers_batch(env: &Env, signer_keys: Vec<SignerKey>) -> Result<(), Error>;
}
