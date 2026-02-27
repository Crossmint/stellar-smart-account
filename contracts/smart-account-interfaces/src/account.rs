use soroban_sdk::contractclient;
use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::auth::types::{PendingRecoveryOpData, RecoveryOperation, Signer, SignerKey};
use crate::error::SmartAccountError;

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

    /// Schedules a recovery operation with time delay. Only callable by recovery signers.
    /// Returns the operation ID (OZ timelock hash).
    fn schedule_recovery(
        env: &Env,
        signer_key: SignerKey,
        operation: RecoveryOperation,
        salt: BytesN<32>,
    ) -> Result<BytesN<32>, SmartAccountError>;

    /// Executes a previously scheduled recovery operation after the delay has passed.
    /// Callable by any signer — the timelock enforces the delay.
    fn execute_recovery(env: &Env, operation_id: BytesN<32>) -> Result<(), SmartAccountError>;

    /// Cancels a pending recovery operation. Only callable by admin signers.
    fn cancel_recovery(env: &Env, operation_id: BytesN<32>) -> Result<(), SmartAccountError>;

    /// Queries the data of a pending recovery operation.
    fn get_recovery_op(
        env: &Env,
        operation_id: BytesN<32>,
    ) -> Result<PendingRecoveryOpData, SmartAccountError>;
}
