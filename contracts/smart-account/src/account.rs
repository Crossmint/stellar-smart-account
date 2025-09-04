use crate::auth::core::authorizer::Authorizer;
use crate::auth::permissions::{PolicyCallback, SignerPolicy, SignerRole};
use crate::auth::proof::SignatureProofs;
use crate::auth::signer::{Signer, SignerKey};
use crate::config::{
    ADMIN_COUNT_KEY, PLUGINS_KEY, TOPIC_PLUGIN, TOPIC_SIGNER, VERB_ADDED, VERB_INSTALLED,
    VERB_REVOKED, VERB_UNINSTALLED, VERB_UNINSTALL_FAILED, VERB_UPDATED,
};
use crate::error::Error;
use crate::events::{
    PluginInstalledEvent, PluginUninstallFailedEvent, PluginUninstalledEvent, SignerAddedEvent,
    SignerRevokedEvent, SignerUpdatedEvent,
};
use crate::handle_nested_result_failure;
use crate::interface::SmartAccountInterface;
use crate::plugin::SmartAccountPluginClient;
use initializable::{only_not_initialized, Initializable};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    map, panic_with_error, Address, Env, Map, Symbol, Vec,
};
use storage::Storage;
use upgradeable::{SmartAccountUpgradeable, SmartAccountUpgradeableAuth};

/// SmartAccount is a multi-signature account contract that provides enhanced security
/// through role-based access control, policy-based authorization, and an extensible plugin system.
///
/// The account supports different signers with different signer roles (Admin, Standard, Restricted) with customizable
/// policies for fine-grained permission management. It also supports external policy delegation and plugin architecture
#[contract]
pub struct SmartAccount;

// Implements SmartAccountUpgradeable trait to allow the contract to be upgraded
// by authorized signers through the upgrade mechanism
upgradeable::impl_upgradeable!(SmartAccount);

impl SmartAccountUpgradeableAuth for SmartAccount {
    fn _require_auth_upgrade(e: &Env) {
        e.current_contract_address().require_auth();
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
            SmartAccount::add_signer(&env, signer).unwrap_or_else(|e| panic_with_error!(env, e));
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

        // Initialize the contract
        SmartAccount::initialize(&env).unwrap_or_else(|e| panic_with_error!(env, e));
    }

    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);
        let key = signer.clone().into();
        let storage = Storage::persistent();
        storage.store::<SignerKey, Signer>(env, &key, &signer)?;

        // Handle role-specific initialization
        match signer.role() {
            SignerRole::Standard(policies) => {
                Self::activate_policies(env, &policies)?;
            }
            SignerRole::Admin => {
                Self::increment_admin_count(env)?;
            }
        }
        env.events()
            .publish((TOPIC_SIGNER, VERB_ADDED), SignerAddedEvent::from(signer));

        Ok(())
    }

    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);
        let key = signer.clone().into();
        let storage = Storage::persistent();
        let old_signer = storage
            .get::<SignerKey, Signer>(env, &key)
            .ok_or(Error::SignerNotFound)?;

        // Handle role transitions: admin count and policy lifecycle callbacks
        Self::handle_role_transition(env, &old_signer.role(), &signer.role())?;

        // Update the signer in storage
        storage.update::<SignerKey, Signer>(env, &key, &signer)?;
        env.events().publish(
            (TOPIC_SIGNER, VERB_UPDATED),
            SignerUpdatedEvent::from(signer),
        );

        Ok(())
    }

    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::persistent();

        let signer_to_revoke = storage
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(Error::SignerNotFound)?;

        if signer_to_revoke.role() == SignerRole::Admin {
            return Err(Error::CannotRevokeAdminSigner);
        }

        storage.delete::<SignerKey>(env, &signer_key)?;
        // Deactivate policies if this is a Standard signer
        if let SignerRole::Standard(policies) = signer_to_revoke.role() {
            Self::deactivate_policies(env, &policies)?;
        }
        env.events().publish(
            (TOPIC_SIGNER, VERB_REVOKED),
            SignerRevokedEvent::from(signer_to_revoke),
        );
        Ok(())
    }

    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, Error> {
        Storage::persistent()
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(Error::SignerNotFound)
    }

    fn has_signer(env: &Env, signer_key: SignerKey) -> Result<bool, Error> {
        Ok(Storage::persistent().has::<SignerKey>(env, &signer_key))
    }

    fn install_plugin(env: &Env, plugin: Address) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        // Store the plugin in the storage
        let storage = Storage::instance();
        let mut existing_plugins = storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap();
        if existing_plugins.contains_key(plugin.clone()) {
            return Err(Error::PluginAlreadyInstalled);
        }
        existing_plugins.set(plugin.clone(), ());
        storage.update::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY, &existing_plugins)?;

        // Call the plugin's on_install callback for initialization
        SmartAccountPluginClient::new(env, &plugin)
            .try_on_install(&env.current_contract_address())
            .map_err(|_| Error::PluginInitializationFailed)?
            .map_err(|_| Error::PluginInitializationFailed)?;

        env.events().publish(
            (TOPIC_PLUGIN, VERB_INSTALLED),
            PluginInstalledEvent { plugin },
        );

        Ok(())
    }

    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::instance();
        let mut existing_plugins = storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap();

        if !existing_plugins.contains_key(plugin.clone()) {
            return Err(Error::PluginNotFound);
        }
        existing_plugins.remove(plugin.clone());
        storage.update(env, &PLUGINS_KEY, &existing_plugins)?;

        // Counterwise to install, we don't want to fail if the plugin's on_uninstall fails,
        // as it would prevent an admin from uninstalling a potentially-malicious plugin.
        let res = SmartAccountPluginClient::new(env, &plugin)
            .try_on_uninstall(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            env.events().publish(
                (TOPIC_PLUGIN, VERB_UNINSTALL_FAILED),
                PluginUninstallFailedEvent {
                    plugin: plugin.clone(),
                },
            );
        });

        env.events().publish(
            (TOPIC_PLUGIN, VERB_UNINSTALLED),
            PluginUninstalledEvent { plugin },
        );

        Ok(())
    }

    fn is_plugin_installed(env: &Env, plugin: Address) -> bool {
        Storage::instance()
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap()
            .contains_key(plugin)
    }
}

// ============================================================================
// Private helper methods for SmartAccount
// ============================================================================

impl SmartAccount {
    /// Handles role transitions including admin count management and policy lifecycle callbacks
    fn handle_role_transition(
        env: &Env,
        old_role: &SignerRole,
        new_role: &SignerRole,
    ) -> Result<(), Error> {
        match (old_role, new_role) {
            // Admin → Standard: decrease admin count, activate policies
            (SignerRole::Admin, SignerRole::Standard(policies)) => {
                Self::decrement_admin_count(env)?;
                Self::activate_policies(env, policies)?;
            }
            // Standard → Admin: increase admin count, deactivate policies
            (SignerRole::Standard(policies), SignerRole::Admin) => {
                Self::increment_admin_count(env)?;
                Self::deactivate_policies(env, policies)?;
            }
            // Standard → Standard: handle policy set changes
            (SignerRole::Standard(old_policies), SignerRole::Standard(new_policies)) => {
                Self::handle_policy_set_changes(env, old_policies, new_policies)?;
            }
            // Admin → Admin: no changes needed
            (SignerRole::Admin, SignerRole::Admin) => {}
        }
        Ok(())
    }

    /// Decrements admin count with validation
    fn decrement_admin_count(env: &Env) -> Result<(), Error> {
        let storage = Storage::persistent();
        let count = storage
            .get::<Symbol, u32>(env, &ADMIN_COUNT_KEY)
            .unwrap_or(0);

        if count <= 1 {
            return Err(Error::CannotDowngradeLastAdmin);
        }

        let new_count = count
            .checked_sub(1)
            .ok_or(Error::CannotDowngradeLastAdmin)?;
        storage.update::<Symbol, u32>(env, &ADMIN_COUNT_KEY, &new_count)?;
        Ok(())
    }

    /// Increments admin count with validation
    fn increment_admin_count(env: &Env) -> Result<(), Error> {
        let storage = Storage::persistent();
        let count = storage
            .get::<Symbol, u32>(env, &ADMIN_COUNT_KEY)
            .unwrap_or(0);
        let new_count = count.checked_add(1).ok_or(Error::MaxSignersReached)?;
        storage.update::<Symbol, u32>(env, &ADMIN_COUNT_KEY, &new_count)?;
        Ok(())
    }

    /// Activates policies by calling their on_add callbacks
    fn activate_policies(env: &Env, policies: &Vec<SignerPolicy>) -> Result<(), Error> {
        for policy in policies {
            policy.on_add(env)?;
        }
        Ok(())
    }

    /// Deactivates policies by calling their on_revoke callbacks
    fn deactivate_policies(env: &Env, policies: &Vec<SignerPolicy>) -> Result<(), Error> {
        for policy in policies {
            policy.on_revoke(env)?;
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
        old_policies: &Vec<SignerPolicy>,
        new_policies: &Vec<SignerPolicy>,
    ) -> Result<(), Error> {
        // Early exit optimizations
        if old_policies.is_empty() && new_policies.is_empty() {
            return Ok(());
        }

        if old_policies.is_empty() {
            // All new policies need to be added
            for policy in new_policies {
                policy.on_add(env)?;
            }
            return Ok(());
        }

        if new_policies.is_empty() {
            // All old policies need to be revoked
            for policy in old_policies {
                policy.on_revoke(env)?;
            }
            return Ok(());
        }

        // Create a simple hash using policy content for constant-time lookup
        let mut new_policy_set = Map::new(env);

        // Build set of new policies
        for policy in new_policies {
            new_policy_set.set(policy, true);
        }

        // Process old policies - find ones to revoke
        for old_policy in old_policies {
            if new_policy_set.contains_key(old_policy.clone()) {
                new_policy_set.set(old_policy, false);
            } else {
                // Policy only in old set, revoke it
                old_policy.on_revoke(env)?;
            }
        }

        // Process new policies - find ones to add
        for policy in new_policies {
            // If still marked as true, it's a new policy that needs to be added
            if new_policy_set.get(policy.clone()).unwrap_or(false) {
                policy.on_add(env)?;
            }
        }

        Ok(())
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
        Authorizer::check(&env, signature_payload, &auth_payloads, &auth_contexts)?;
        Authorizer::call_plugins_on_auth(&env, &auth_contexts)?;
        Ok(())
    }
}
