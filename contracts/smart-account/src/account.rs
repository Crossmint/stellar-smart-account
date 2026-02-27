use crate::auth::core::authorizer::Authorizer;
use crate::auth::permissions::PolicyCallback;
use crate::auth::proof::SignatureProofs;
use crate::config::{
    ADMIN_COUNT_KEY, CONTRACT_VERSION_KEY, CURRENT_CONTRACT_VERSION, INSTANCE_EXTEND_TO,
    INSTANCE_TTL_THRESHOLD, PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD, PLUGINS_KEY,
};
use crate::error::Error;
use crate::events::{
    PluginInstalledEvent, PluginUninstallFailedEvent, PluginUninstalledEvent,
    RecoveryCancelledEvent, RecoveryExecutedEvent, RecoveryScheduledEvent, SignerAddedEvent,
    SignerRevokedEvent, SignerUpdatedEvent,
};
use upgradeable::{UpgradeCompletedEvent, UpgradeStartedEvent};
use crate::handle_nested_result_failure;
use crate::migration::{run_migration, MigrationData};
use crate::plugin::SmartAccountPluginClient;
use initializable::{only_not_initialized, Initializable};
use smart_account_interfaces::SmartAccountError;
pub use smart_account_interfaces::SmartAccountInterface;
use smart_account_interfaces::{
    MultisigSigner, PendingRecoveryOpData, RecoveryOperation, RecoveryStorageKey, Signer,
    SignerKey, SignerPolicy, SignerRole,
};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    map, panic_with_error, Address, BytesN, Env, IntoVal, Map, Symbol, Vec,
};
use stellar_governance::timelock;
use storage::Storage;
use upgradeable::{
    SmartAccountUpgradeableAuth, SmartAccountUpgradeableMigratable,
    SmartAccountUpgradeableMigratableInternal,
};

/// SmartAccount is a multi-signature account contract that provides enhanced security
/// through role-based access control, policy-based authorization, and an extensible plugin system.
///
/// The account supports different signers with different signer roles (Admin, Standard, Recovery) with customizable
/// policies for fine-grained permission management. It also supports external policy delegation and plugin architecture.
#[contract]
pub struct SmartAccount;

// Implements upgrade and migrate via the SmartAccountUpgradeableMigratable trait
// from the `upgradeable` crate. This provides the standard two-phase upgrade flow:
// upgrade() swaps WASM + sets MIGRATING flag, migrate() runs data migration + clears flag.
//
// SmartAccountUpgradeableAuth provides the authorization check.
// SmartAccountUpgradeableMigratableInternal provides the migration callback.
// SmartAccountUpgradeableMigratable ties them together with the public entry points.
impl SmartAccountUpgradeableAuth for SmartAccount {
    fn _require_auth_upgrade(e: &Env) {
        e.current_contract_address().require_auth();
    }
}

impl SmartAccountUpgradeableMigratableInternal for SmartAccount {
    type MigrationData = MigrationData;

    fn _migrate(e: &Env, migration_data: &Self::MigrationData) {
        run_migration(e, migration_data);
    }
}

#[contractimpl]
impl SmartAccountUpgradeableMigratable for SmartAccount {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>) {
        Self::_require_auth_upgrade(e);
        upgradeable::enable_migration(e);
        UpgradeStartedEvent {
            contract_address: e.current_contract_address(),
        }
        .publish(e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    fn migrate(e: &Env, migration_data: MigrationData) {
        Self::_require_auth_upgrade(e);
        upgradeable::ensure_can_complete_migration(e);
        Self::_migrate(e, &migration_data);
        upgradeable::complete_migration(e);
        UpgradeCompletedEvent {
            contract_address: e.current_contract_address(),
        }
        .publish(e);
    }
}

// Implements Initializable trait to allow the contract to be initialized.
// that allows the deployer to set the initial signer configuration without
// an explicit authorization for those signers
impl Initializable for SmartAccount {}

impl SmartAccount {
    /// Only requires authorization if the contract is already initialized.
    pub fn require_auth_if_initialized(env: &Env) {
        if Self::is_initialized(env) {
            env.current_contract_address().require_auth();
        }
    }
}

// ============================================================================
// SmartAccountInterface implementation
// ============================================================================

/// Implementation of the SmartAccountInterface trait that defines the public interface
/// for all administrative operations on the smart account.
#[contractimpl]
impl SmartAccountInterface for SmartAccount {
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>) {
        only_not_initialized!(&env);
        Self::extend_instance_ttl(&env);

        // Check that there is at least one admin signer to prevent the contract from being locked out.
        if !signers.iter().any(|s| s.role() == SignerRole::Admin) {
            panic_with_error!(env, Error::InsufficientPermissionsOnCreation);
        }

        // Initialize admin count to 0 before adding signers
        Storage::persistent()
            .store(&env, &ADMIN_COUNT_KEY, &0u32)
            .unwrap_or_else(|e| panic_with_error!(env, Error::from(e)));

        // Register signers. Duplication will fail
        for signer in signers.iter() {
            SmartAccount::add_signer_internal(&env, signer)
                .unwrap_or_else(|e| panic_with_error!(env, e));
        }

        // Initialize plugins storage
        let storage = Storage::instance();
        storage
            .store::<Symbol, Map<Address, ()>>(&env, &PLUGINS_KEY, &map![&env])
            .unwrap();
        // Install plugins
        for plugin in plugins {
            SmartAccount::install_plugin(&env, plugin)
                .unwrap_or_else(|e| panic_with_error!(env, e));
        }

        // Set the contract version so future migrations know the starting point
        env.storage()
            .instance()
            .set(&CONTRACT_VERSION_KEY, &CURRENT_CONTRACT_VERSION);

        // Initialize the contract
        SmartAccount::initialize(&env).unwrap_or_else(|e| panic_with_error!(env, e));
    }

    fn add_signer(env: &Env, signer: Signer) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);
        Self::add_signer_internal(env, signer)
    }

    fn update_signer(env: &Env, signer: Signer) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);
        Self::update_signer_internal(env, signer)
    }

    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);
        Self::revoke_signer_internal(env, signer_key)
    }

    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, SmartAccountError> {
        Storage::persistent()
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(SmartAccountError::SignerNotFound)
    }

    fn has_signer(env: &Env, signer_key: SignerKey) -> Result<bool, SmartAccountError> {
        Ok(Storage::persistent().has::<SignerKey>(env, &signer_key))
    }

    fn install_plugin(env: &Env, plugin: Address) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);

        // Store the plugin in the storage
        let storage = Storage::instance();
        let mut existing_plugins = storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap();
        if existing_plugins.contains_key(plugin.clone()) {
            return Err(SmartAccountError::PluginAlreadyInstalled);
        }
        existing_plugins.set(plugin.clone(), ());
        storage.update::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY, &existing_plugins)?;

        // Call the plugin's on_install callback for initialization
        SmartAccountPluginClient::new(env, &plugin)
            .try_on_install(&env.current_contract_address())
            .map_err(|_| SmartAccountError::PluginInitializationFailed)?
            .map_err(|_| SmartAccountError::PluginInitializationFailed)?;

        PluginInstalledEvent { plugin }.publish(env);

        Ok(())
    }

    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::instance();
        let mut existing_plugins = storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap();

        if !existing_plugins.contains_key(plugin.clone()) {
            return Err(SmartAccountError::PluginNotFound);
        }
        existing_plugins.remove(plugin.clone());
        storage.update(env, &PLUGINS_KEY, &existing_plugins)?;

        // Counterwise to install, we don't want to fail if the plugin's on_uninstall fails,
        // as it would prevent an admin from uninstalling a potentially-malicious plugin.
        let res = SmartAccountPluginClient::new(env, &plugin)
            .try_on_uninstall(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            PluginUninstallFailedEvent {
                plugin: plugin.clone(),
            }
            .publish(env);
        });

        PluginUninstalledEvent { plugin }.publish(env);

        Ok(())
    }

    fn is_plugin_installed(env: &Env, plugin: Address) -> bool {
        Storage::instance()
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap()
            .contains_key(plugin)
    }

    // ========================================================================
    // Recovery operations
    // ========================================================================

    fn schedule_recovery(
        env: &Env,
        signer_key: SignerKey,
        operation: RecoveryOperation,
        salt: BytesN<32>,
    ) -> Result<BytesN<32>, SmartAccountError> {
        Self::require_auth_if_initialized(env);

        // Look up the signer and verify it has the Recovery role
        let signer = Storage::persistent()
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(SmartAccountError::SignerNotFound)?;

        let (delay_secs, prevent_deletion) = match signer.role() {
            SignerRole::Recovery(delay, prevent) => (delay, prevent),
            _ => return Err(SmartAccountError::RecoverySignerRequired),
        };

        // Enforce prevent_deletion restriction
        if prevent_deletion {
            match &operation {
                RecoveryOperation::UpdateSigner(_) | RecoveryOperation::RevokeSigner(_) => {
                    return Err(SmartAccountError::RecoveryPreventDeletionViolation);
                }
                RecoveryOperation::AddSigner(_) => {}
            }
        }

        // Validate the inner operation before scheduling
        match &operation {
            RecoveryOperation::AddSigner(inner_signer)
            | RecoveryOperation::UpdateSigner(inner_signer) => {
                if let Signer::Multisig(ref multisig, _) = inner_signer {
                    Self::validate_multisig(env, multisig)?;
                }
                Self::validate_signer_expiration(env, inner_signer)?;
                if let SignerRole::Standard(Some(ref policies), _) = inner_signer.role() {
                    if policies.is_empty() {
                        return Err(SmartAccountError::InvalidPolicy);
                    }
                }
                if let SignerRole::Recovery(delay, _) = inner_signer.role() {
                    if delay == 0 {
                        return Err(SmartAccountError::InvalidRecoveryDelay);
                    }
                }
            }
            RecoveryOperation::RevokeSigner(_) => {}
        }

        // Ensure min_delay is initialized (lazy init, idempotent)
        Self::ensure_timelock_initialized(env);

        // Build the OZ Operation struct
        let oz_operation = Self::build_oz_operation(env, &operation, &salt);
        let operation_id = timelock::hash_operation(env, &oz_operation);

        // Schedule via OZ timelock (delay is in seconds, matching v0.6.0 API)
        timelock::schedule_operation(env, &oz_operation, delay_secs);

        // Extend TTL on the timelock storage entry
        env.storage().persistent().extend_ttl(
            &timelock::TimelockStorageKey::Timestamp(operation_id.clone()),
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );

        // Store our recovery operation data (including salt for later reconstruction)
        let storage_key = RecoveryStorageKey::PendingOp(operation_id.clone());
        let data = PendingRecoveryOpData {
            operation: operation.clone(),
            scheduled_by: signer_key,
            scheduled_at: env.ledger().timestamp(),
            salt,
        };
        Storage::persistent()
            .store::<RecoveryStorageKey, PendingRecoveryOpData>(env, &storage_key, &data)?;

        env.storage().persistent().extend_ttl(
            &storage_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );

        let execute_after = env.ledger().timestamp() + (delay_secs as u64);
        RecoveryScheduledEvent {
            operation_id: operation_id.clone(),
            operation,
            scheduled_by: data.scheduled_by,
            execute_after,
        }
        .publish(env);

        Ok(operation_id)
    }

    fn execute_recovery(
        env: &Env,
        operation_id: BytesN<32>,
    ) -> Result<(), SmartAccountError> {
        Self::require_auth_if_initialized(env);

        // Look up the pending recovery data
        let storage_key = RecoveryStorageKey::PendingOp(operation_id.clone());
        let data = Storage::persistent()
            .get::<RecoveryStorageKey, PendingRecoveryOpData>(env, &storage_key)
            .ok_or(SmartAccountError::RecoveryOperationNotFound)?;

        // Rebuild the OZ Operation for hash validation and state check
        let oz_operation = Self::rebuild_oz_operation(env, &data);

        // Validate readiness and mark as Done (no cross-contract call)
        timelock::set_execute_operation(env, &oz_operation);

        // Perform the actual signer operation internally
        match &data.operation {
            RecoveryOperation::AddSigner(signer) => {
                Self::add_signer_internal(env, signer.clone())?;
            }
            RecoveryOperation::UpdateSigner(signer) => {
                Self::update_signer_internal(env, signer.clone())?;
            }
            RecoveryOperation::RevokeSigner(key) => {
                Self::revoke_signer_internal(env, key.clone())?;
            }
        }

        // Clean up pending operation data
        Storage::persistent().delete::<RecoveryStorageKey>(env, &storage_key)?;

        RecoveryExecutedEvent {
            operation_id,
            operation: data.operation,
        }
        .publish(env);

        Ok(())
    }

    fn cancel_recovery(
        env: &Env,
        operation_id: BytesN<32>,
    ) -> Result<(), SmartAccountError> {
        // Only admins can cancel (enforced by __check_auth since this is an admin op)
        Self::require_auth_if_initialized(env);

        // Verify the pending operation exists
        let storage_key = RecoveryStorageKey::PendingOp(operation_id.clone());
        if !Storage::persistent().has::<RecoveryStorageKey>(env, &storage_key) {
            return Err(SmartAccountError::RecoveryOperationNotFound);
        }

        // Cancel via OZ timelock
        timelock::cancel_operation(env, &operation_id);

        // Clean up our storage
        Storage::persistent().delete::<RecoveryStorageKey>(env, &storage_key)?;

        RecoveryCancelledEvent { operation_id }.publish(env);

        Ok(())
    }

    fn get_recovery_op(
        env: &Env,
        operation_id: BytesN<32>,
    ) -> Result<PendingRecoveryOpData, SmartAccountError> {
        let storage_key = RecoveryStorageKey::PendingOp(operation_id);
        Storage::persistent()
            .get::<RecoveryStorageKey, PendingRecoveryOpData>(env, &storage_key)
            .ok_or(SmartAccountError::RecoveryOperationNotFound)
    }
}

// ============================================================================
// Private helper methods for SmartAccount
// ============================================================================

impl SmartAccount {
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_EXTEND_TO);
    }

    // ========================================================================
    // Internal signer operations (no auth check — used by recovery execute)
    // ========================================================================

    fn add_signer_internal(env: &Env, signer: Signer) -> Result<(), SmartAccountError> {
        if let Signer::Multisig(ref multisig, _) = signer {
            Self::validate_multisig(env, multisig)?;
        }
        Self::validate_signer_expiration(env, &signer)?;

        // Validate: Some(empty_vec) is not allowed — use None for no policies
        if let SignerRole::Standard(Some(ref policies), _) = signer.role() {
            if policies.is_empty() {
                return Err(SmartAccountError::InvalidPolicy);
            }
        }

        // Validate recovery delay
        if let SignerRole::Recovery(delay, _) = signer.role() {
            if delay == 0 {
                return Err(SmartAccountError::InvalidRecoveryDelay);
            }
        }

        let key = signer.clone().into();
        let storage = Storage::persistent();
        storage.store::<SignerKey, Signer>(env, &key, &signer)?;

        // Handle role-specific initialization
        match signer.role() {
            SignerRole::Standard(policies, _) => {
                Self::activate_policies(env, &key, &policies)?;
            }
            SignerRole::Admin => {
                Self::increment_admin_count(env)?;
            }
            SignerRole::Recovery(_, _) => {
                // No policies or admin count changes for recovery signers
            }
        }
        SignerAddedEvent::from(signer).publish(env);

        Ok(())
    }

    fn update_signer_internal(env: &Env, signer: Signer) -> Result<(), SmartAccountError> {
        if let Signer::Multisig(ref multisig, _) = signer {
            Self::validate_multisig(env, multisig)?;
        }
        Self::validate_signer_expiration(env, &signer)?;

        // Validate: Some(empty_vec) is not allowed — use None for no policies
        if let SignerRole::Standard(Some(ref policies), _) = signer.role() {
            if policies.is_empty() {
                return Err(SmartAccountError::InvalidPolicy);
            }
        }

        // Validate recovery delay
        if let SignerRole::Recovery(delay, _) = signer.role() {
            if delay == 0 {
                return Err(SmartAccountError::InvalidRecoveryDelay);
            }
        }

        let key = signer.clone().into();
        let storage = Storage::persistent();
        let old_signer = storage
            .get::<SignerKey, Signer>(env, &key)
            .ok_or(SmartAccountError::SignerNotFound)?;

        // Handle role transitions: admin count and policy lifecycle callbacks
        Self::handle_role_transition(env, &key, &old_signer.role(), &signer.role())?;

        // Update the signer in storage
        storage.update::<SignerKey, Signer>(env, &key, &signer)?;
        SignerUpdatedEvent::from(signer).publish(env);

        Ok(())
    }

    fn revoke_signer_internal(env: &Env, signer_key: SignerKey) -> Result<(), SmartAccountError> {
        let storage = Storage::persistent();

        let signer_to_revoke = storage
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(SmartAccountError::SignerNotFound)?;

        if signer_to_revoke.role() == SignerRole::Admin {
            return Err(SmartAccountError::CannotRevokeAdminSigner);
        }

        storage.delete::<SignerKey>(env, &signer_key)?;
        // Deactivate policies if this is a Standard signer
        if let SignerRole::Standard(policies, _) = signer_to_revoke.role() {
            Self::deactivate_policies(env, &signer_key, &policies)?;
        }
        // Recovery signers have no policies to deactivate.
        // Pending recovery operations remain valid (must be cancelled separately).

        SignerRevokedEvent::from(signer_to_revoke).publish(env);
        Ok(())
    }

    // ========================================================================
    // Role transition handling
    // ========================================================================

    /// Handles role transitions including admin count management and policy lifecycle callbacks.
    /// Expanded to handle the 3x3 matrix of Admin/Standard/Recovery transitions.
    fn handle_role_transition(
        env: &Env,
        signer_key: &SignerKey,
        old_role: &SignerRole,
        new_role: &SignerRole,
    ) -> Result<(), SmartAccountError> {
        match (old_role, new_role) {
            // Admin → Admin: no changes needed
            (SignerRole::Admin, SignerRole::Admin) => {}
            // Admin → Standard: decrease admin count, activate policies
            (SignerRole::Admin, SignerRole::Standard(policies, _)) => {
                Self::decrement_admin_count(env)?;
                Self::activate_policies(env, signer_key, policies)?;
            }
            // Admin → Recovery: decrease admin count
            (SignerRole::Admin, SignerRole::Recovery(_, _)) => {
                Self::decrement_admin_count(env)?;
            }
            // Standard → Admin: increase admin count, deactivate policies
            (SignerRole::Standard(policies, _), SignerRole::Admin) => {
                Self::increment_admin_count(env)?;
                Self::deactivate_policies(env, signer_key, policies)?;
            }
            // Standard → Standard: handle policy set changes
            (SignerRole::Standard(old_policies, _), SignerRole::Standard(new_policies, _)) => {
                Self::handle_policy_set_changes(env, signer_key, old_policies, new_policies)?;
            }
            // Standard → Recovery: deactivate policies
            (SignerRole::Standard(policies, _), SignerRole::Recovery(_, _)) => {
                Self::deactivate_policies(env, signer_key, policies)?;
            }
            // Recovery → Admin: increase admin count
            (SignerRole::Recovery(_, _), SignerRole::Admin) => {
                Self::increment_admin_count(env)?;
            }
            // Recovery → Standard: activate policies
            (SignerRole::Recovery(_, _), SignerRole::Standard(policies, _)) => {
                Self::activate_policies(env, signer_key, policies)?;
            }
            // Recovery → Recovery: config update only (delay/prevent_deletion)
            (SignerRole::Recovery(_, _), SignerRole::Recovery(_, _)) => {}
        }
        Ok(())
    }

    // ========================================================================
    // Admin count management
    // ========================================================================

    /// Decrements admin count with validation
    fn decrement_admin_count(env: &Env) -> Result<(), SmartAccountError> {
        let storage = Storage::persistent();
        let count = storage
            .get::<Symbol, u32>(env, &ADMIN_COUNT_KEY)
            .unwrap_or(0);

        if count <= 1 {
            return Err(SmartAccountError::CannotDowngradeLastAdmin);
        }

        let new_count = count
            .checked_sub(1)
            .ok_or(SmartAccountError::CannotDowngradeLastAdmin)?;
        storage.update::<Symbol, u32>(env, &ADMIN_COUNT_KEY, &new_count)?;
        Ok(())
    }

    /// Increments admin count with validation
    fn increment_admin_count(env: &Env) -> Result<(), SmartAccountError> {
        let storage = Storage::persistent();
        let count = storage
            .get::<Symbol, u32>(env, &ADMIN_COUNT_KEY)
            .unwrap_or(0);
        let new_count = count
            .checked_add(1)
            .ok_or(SmartAccountError::MaxSignersReached)?;
        storage.update::<Symbol, u32>(env, &ADMIN_COUNT_KEY, &new_count)?;
        Ok(())
    }

    // ========================================================================
    // Validation helpers
    // ========================================================================

    /// Validates that a signer's expiration (if set) is in the future.
    fn validate_signer_expiration(env: &Env, signer: &Signer) -> Result<(), SmartAccountError> {
        let expiration = signer.expiration();
        if expiration > 0 && expiration <= env.ledger().timestamp() {
            return Err(SmartAccountError::SignerExpired);
        }
        Ok(())
    }

    /// Validates multisig signer configuration
    fn validate_multisig(env: &Env, multisig: &MultisigSigner) -> Result<(), SmartAccountError> {
        if multisig.members.is_empty() || multisig.threshold == 0 {
            return Err(SmartAccountError::MultisigInvalidThreshold);
        }
        if multisig.threshold > multisig.members.len() {
            return Err(SmartAccountError::MultisigInvalidThreshold);
        }
        // Check for duplicate members by converting each to a SignerKey
        let mut seen_keys: Map<SignerKey, bool> = Map::new(env);
        for member in multisig.members.iter() {
            let key: SignerKey = member.into();
            if seen_keys.contains_key(key.clone()) {
                return Err(SmartAccountError::MultisigDuplicatedMember);
            }
            seen_keys.set(key, true);
        }
        Ok(())
    }

    // ========================================================================
    // Policy lifecycle
    // ========================================================================

    /// Activates policies by calling their on_add callbacks
    fn activate_policies(
        env: &Env,
        signer_key: &SignerKey,
        policies: &Option<Vec<SignerPolicy>>,
    ) -> Result<(), SmartAccountError> {
        if let Some(policies) = policies {
            for policy in policies {
                policy.on_add(env, signer_key)?;
            }
        }
        Ok(())
    }

    /// Deactivates policies by calling their on_revoke callbacks
    fn deactivate_policies(
        env: &Env,
        signer_key: &SignerKey,
        policies: &Option<Vec<SignerPolicy>>,
    ) -> Result<(), SmartAccountError> {
        if let Some(policies) = policies {
            for policy in policies {
                policy.on_revoke(env, signer_key)?;
            }
        }
        Ok(())
    }

    /// Handles changes to a policy set by calling appropriate callbacks
    ///
    /// - Policies only in old set: on_revoke() called (removed)
    /// - Policies only in new set: on_add() called (added)
    /// - Policies in both sets: no callbacks (unchanged)
    fn handle_policy_set_changes(
        env: &Env,
        signer_key: &SignerKey,
        old_policies: &Option<Vec<SignerPolicy>>,
        new_policies: &Option<Vec<SignerPolicy>>,
    ) -> Result<(), SmartAccountError> {
        let empty = Vec::new(env);
        let old = old_policies.as_ref().unwrap_or(&empty);
        let new = new_policies.as_ref().unwrap_or(&empty);

        // Early exit optimizations
        if old.is_empty() && new.is_empty() {
            return Ok(());
        }

        if old.is_empty() {
            // All new policies need to be added
            for policy in new.iter() {
                policy.on_add(env, signer_key)?;
            }
            return Ok(());
        }

        if new.is_empty() {
            // All old policies need to be revoked
            for policy in old.iter() {
                policy.on_revoke(env, signer_key)?;
            }
            return Ok(());
        }

        // Create a simple hash using policy content for constant-time lookup
        let mut new_policy_set = Map::new(env);

        // Build set of new policies
        for policy in new.iter() {
            new_policy_set.set(policy, true);
        }

        // Process old policies - find ones to revoke
        for old_policy in old.iter() {
            if new_policy_set.contains_key(old_policy.clone()) {
                new_policy_set.set(old_policy, false);
            } else {
                // Policy only in old set, revoke it
                old_policy.on_revoke(env, signer_key)?;
            }
        }

        // Process new policies - find ones to add
        for policy in new.iter() {
            // If still marked as true, it's a new policy that needs to be added
            if new_policy_set.get(policy.clone()).unwrap_or(false) {
                policy.on_add(env, signer_key)?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // Recovery helpers
    // ========================================================================

    /// Ensures the OZ timelock min_delay is initialized (lazy, idempotent).
    /// In v0.6.0, MinDelay is stored in instance storage.
    fn ensure_timelock_initialized(env: &Env) {
        if !env
            .storage()
            .instance()
            .has(&timelock::TimelockStorageKey::MinDelay)
        {
            timelock::set_min_delay(env, 0);
        }
    }

    /// Builds an OZ Operation struct from a RecoveryOperation and salt.
    fn build_oz_operation(
        env: &Env,
        recovery_op: &RecoveryOperation,
        salt: &BytesN<32>,
    ) -> timelock::Operation {
        timelock::Operation {
            target: env.current_contract_address(),
            function: Symbol::new(env, "execute_recovery"),
            args: Vec::from_array(env, [recovery_op.clone().into_val(env)]),
            predecessor: BytesN::from_array(env, &[0u8; 32]),
            salt: salt.clone(),
        }
    }

    /// Rebuilds an OZ Operation from stored PendingRecoveryOpData for hash validation.
    /// Uses the salt stored in PendingRecoveryOpData to reconstruct the exact same
    /// Operation struct that was used during scheduling.
    fn rebuild_oz_operation(
        env: &Env,
        data: &PendingRecoveryOpData,
    ) -> timelock::Operation {
        Self::build_oz_operation(env, &data.operation, &data.salt)
    }
}

// ============================================================================
// IsDeployed implementation
// ============================================================================

/// Simple trait to allow an external contract to check if the smart account
/// is live
pub trait IsDeployed {
    fn is_deployed(env: &Env) -> bool;
}

#[contractimpl]
impl IsDeployed for SmartAccount {
    fn is_deployed(_env: &Env) -> bool {
        true
    }
}

// ============================================================================
// CustomAccountInterface implementation
// ============================================================================

/// Implementation of Soroban's CustomAccountInterface for smart account authorization.
///
/// This provides the custom authorization logic that the Soroban runtime uses
/// to verify whether operations are authorized by the account's signers.
#[contractimpl]
impl CustomAccountInterface for SmartAccount {
    /// The signature type used for authorization proofs.
    /// Contains a map of signer keys to their corresponding signature proofs.
    type Signature = SignatureProofs;
    type Error = Error;

    /// Custom authorization function invoked by the Soroban runtime.
    ///
    /// This function implements the account's authorization logic with optimizations for Stellar costs:
    /// 1. Verifies that all provided signatures are cryptographically valid
    /// 2. Checks that at least one authorized signer has approved each operation
    /// 3. Ensures signers have the required permissions for the requested operations
    ///
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `signature_payload` - Hash of the data that was signed
    /// * `auth_payloads` - Map of signer keys to their signature proofs
    /// * `auth_contexts` - List of operations being authorized
    ///
    /// # Returns
    /// * `Ok(())` if authorization succeeds
    /// * `Err(Error)` if authorization fails for any reason
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        auth_payloads: SignatureProofs,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        Authorizer::check(&env, signature_payload, &auth_payloads, &auth_contexts)?;
        Authorizer::call_plugins_on_auth(&env, &auth_contexts)?;
        Ok(())
    }
}
