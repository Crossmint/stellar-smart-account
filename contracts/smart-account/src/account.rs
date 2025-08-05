use crate::auth::core::AuthorizationService;
use crate::auth::permissions::{PolicyCallback, SignerRole};
use crate::auth::proof::SignatureProofs;
use crate::auth::signer::{Signer, SignerKey};
use crate::config::{
    ADDED_EVENT, CALLBACK_FAILED_EVENT, INSTALLED_EVENT, PLUGINS_KEY, PLUGIN_TOPIC, REVOKED_EVENT,
    SIGNER_TOPIC, UNINSTALLED_EVENT, UPDATED_EVENT,
};
use crate::error::Error;
use crate::events::{
    PluginCallbackFailedEvent, PluginInstalledEvent, PluginUninstalledEvent, SignerAddedEvent,
    SignerRevokedEvent, SignerUpdatedEvent,
};
use crate::interface::SmartAccountInterface;
use crate::plugin::{PluginMetadata, SmartAccountPluginClient};
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
/// through role-based access control and policy-based authorization.
///
/// The account supports different signers with different signer roles (Admin, Standard, Restricted) with customizable
/// policies for fine-grained permission management.
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

    fn count_admin_signers(_env: &Env) -> u32 {
        1
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

        // Register signers. Duplication will fail
        for signer in signers.iter() {
            SmartAccount::add_signer(&env, signer).unwrap_or_else(|e| panic_with_error!(env, e));
        }

        // Initialize plugins storage
        Storage::default()
            .store::<Symbol, Map<Address, PluginMetadata>>(&env, &PLUGINS_KEY, &map![&env])
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
        Storage::default().store::<SignerKey, Signer>(env, &key, &signer)?;

        if let SignerRole::Restricted(policies) = signer.role() {
            for policy in policies {
                policy.on_add(env)?;
            }
        }
        env.events()
            .publish((SIGNER_TOPIC, ADDED_EVENT), SignerAddedEvent::from(signer));

        Ok(())
    }

    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);
        let key = signer.clone().into();

        if let Some(existing_signer) = Storage::default().get::<SignerKey, Signer>(env, &key) {
            if existing_signer.role() == SignerRole::Admin && signer.role() != SignerRole::Admin {
                let admin_count = Self::count_admin_signers(env);
                if admin_count <= 1 {
                    return Err(Error::CannotRevokeLastAdmin);
                }
            }
        }

        Storage::default().update::<SignerKey, Signer>(env, &key, &signer)?;

        env.events().publish(
            (SIGNER_TOPIC, UPDATED_EVENT),
            SignerUpdatedEvent::from(signer),
        );

        Ok(())
    }

    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::default();

        let signer_to_revoke = storage
            .get::<SignerKey, Signer>(env, &signer_key)
            .ok_or(Error::SignerNotFound)?;

        if signer_to_revoke.role() == SignerRole::Admin {
            return Err(Error::CannotRevokeAdminSigner);
        }
        storage.delete::<SignerKey>(env, &signer_key)?;
        env.events().publish(
            (SIGNER_TOPIC, REVOKED_EVENT),
            SignerRevokedEvent::from(signer_to_revoke),
        );
        Ok(())
    }

    fn install_plugin(env: &Env, plugin: Address) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        // Store the plugin in the storage
        let storage = Storage::default();
        let mut existing_plugins = storage
            .get::<Symbol, Map<Address, PluginMetadata>>(env, &PLUGINS_KEY)
            .unwrap();
        if existing_plugins.contains_key(plugin.clone()) {
            return Err(Error::PluginAlreadyInstalled);
        }

        let plugin_metadata = PluginMetadata {
            address: plugin.clone(),
            version: 1,
            dependencies: Vec::new(env),
            installed_at: env.ledger().timestamp(),
        };
        existing_plugins.set(plugin.clone(), plugin_metadata);
        storage.update::<Symbol, Map<Address, PluginMetadata>>(
            env,
            &PLUGINS_KEY,
            &existing_plugins,
        )?;

        // Call the plugin's on_install callback for initialization
        SmartAccountPluginClient::new(env, &plugin)
            .try_on_install(&env.current_contract_address())
            .map_err(|_| Error::PluginInitializationFailed)?
            .map_err(|_| Error::PluginInitializationFailed)?;

        env.events().publish(
            (PLUGIN_TOPIC, INSTALLED_EVENT),
            PluginInstalledEvent { plugin },
        );

        Ok(())
    }

    fn uninstall_plugin(env: &Env, plugin: Address) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let mut existing_plugins = Storage::default()
            .get::<Symbol, Map<Address, PluginMetadata>>(env, &PLUGINS_KEY)
            .unwrap();

        if !existing_plugins.contains_key(plugin.clone()) {
            return Err(Error::PluginNotFound);
        }
        existing_plugins.remove(plugin.clone());

        // as it would prevent an admin from uninstalling a potentially-malicious plugin.
        if SmartAccountPluginClient::new(env, &plugin)
            .try_on_uninstall(&env.current_contract_address())
            .is_err()
        {
            env.events().publish(
                (PLUGIN_TOPIC, CALLBACK_FAILED_EVENT),
                PluginCallbackFailedEvent {
                    plugin: plugin.clone(),
                },
            );
        }

        env.events().publish(
            (PLUGIN_TOPIC, UNINSTALLED_EVENT),
            PluginUninstalledEvent { plugin },
        );

        Ok(())
    }

    fn add_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        for signer in signers.iter() {
            let key = signer.clone().into();
            Storage::default().store::<SignerKey, Signer>(env, &key, &signer)?;

            if let SignerRole::Restricted(policies) = signer.role() {
                for policy in policies {
                    policy.on_add(env)?;
                }
            }
            env.events().publish(
                (SIGNER_TOPIC, ADDED_EVENT),
                SignerAddedEvent::from(signer.clone()),
            );
        }

        Ok(())
    }

    fn update_signers_batch(env: &Env, signers: Vec<Signer>) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let admin_count = Self::count_admin_signers(env);
        let mut admin_downgrades = 0u32;

        for signer in signers.iter() {
            let key = signer.clone().into();
            if let Some(existing_signer) = Storage::default().get::<SignerKey, Signer>(env, &key) {
                if existing_signer.role() == SignerRole::Admin && signer.role() != SignerRole::Admin
                {
                    admin_downgrades += 1;
                }
            }
        }

        if admin_count <= admin_downgrades {
            return Err(Error::CannotRevokeLastAdmin);
        }

        for signer in signers.iter() {
            let key = signer.clone().into();
            Storage::default().update::<SignerKey, Signer>(env, &key, &signer)?;

            env.events().publish(
                (SIGNER_TOPIC, UPDATED_EVENT),
                SignerUpdatedEvent::from(signer.clone()),
            );
        }

        Ok(())
    }

    fn revoke_signers_batch(env: &Env, signer_keys: Vec<SignerKey>) -> Result<(), Error> {
        Self::require_auth_if_initialized(env);

        let storage = Storage::default();

        for signer_key in signer_keys.iter() {
            let signer_to_revoke = storage
                .get::<SignerKey, Signer>(env, &signer_key)
                .ok_or(Error::SignerNotFound)?;

            if signer_to_revoke.role() == SignerRole::Admin {
                return Err(Error::CannotRevokeAdminSigner);
            }
        }

        for signer_key in signer_keys.iter() {
            let signer_to_revoke = storage
                .get::<SignerKey, Signer>(env, &signer_key)
                .ok_or(Error::SignerNotFound)?;

            storage.delete::<SignerKey>(env, &signer_key)?;
            env.events().publish(
                (SIGNER_TOPIC, REVOKED_EVENT),
                SignerRevokedEvent::from(signer_to_revoke),
            );
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
        AuthorizationService::check_authorization(
            &env,
            signature_payload,
            &auth_payloads,
            &auth_contexts,
        )?;

        for (plugin, _) in Storage::default()
            .get::<Symbol, Map<Address, PluginMetadata>>(&env, &PLUGINS_KEY)
            .unwrap()
            .iter()
        {
            SmartAccountPluginClient::new(&env, &plugin)
                .on_auth(&env.current_contract_address(), &auth_contexts);
        }

        Ok(())
    }
}

impl SmartAccount {}
