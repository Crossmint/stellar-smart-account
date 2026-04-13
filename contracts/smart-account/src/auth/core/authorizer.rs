/// Authorization service that verifies proofs and enforces role/policy checks.
use crate::auth::permissions::AuthorizationCheck;
use crate::auth::proof::SignatureProofs;
use crate::auth::signers::SignatureVerifier as _;
use crate::config::{
    ADMIN_COUNT_KEY, PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD, PLUGINS_KEY, TOPIC_PLUGIN,
    VERB_AUTH_FAILED,
};
use crate::error::Error;
use crate::events::PluginAuthFailedEvent;
use smart_account_interfaces::SmartAccountPluginClient;
use smart_account_interfaces::{Signer, SignerKey, SignerRole};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{crypto::Hash, Address, Env, InvokeError, Map, String, Symbol, TryFromVal, Vec};
use storage::Storage;

pub struct Authorizer;

impl Authorizer {
    pub fn check(
        env: &Env,
        signature_payload: Hash<32>,
        auth_payloads: &SignatureProofs,
        auth_contexts: &Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::persistent();
        let SignatureProofs(proof_map) = auth_payloads;

        if proof_map.is_empty() {
            return Err(Error::NoProofsInAuthEntry);
        }

        let mut admin_signers = Vec::new(env);
        let mut standard_signers = Vec::new(env);

        for (signer_key, proof) in proof_map.iter() {
            let signer = storage
                .get::<SignerKey, Signer>(env, &signer_key)
                .ok_or(Error::SignerNotFound)?;

            // Reject expired signers early, before expensive signature verification
            if signer.is_expired(env) {
                return Err(Error::SignerExpired);
            }

            env.storage().persistent().extend_ttl(
                &signer_key,
                PERSISTENT_TTL_THRESHOLD,
                PERSISTENT_EXTEND_TO,
            );
            signer.verify(env, &signature_payload, &proof)?;

            match signer.role() {
                SignerRole::Admin => admin_signers.push_back(signer),
                SignerRole::Standard(_, _) => standard_signers.push_back(signer),
            }
        }

        // Keep the admin count alive alongside signer entries
        if env.storage().persistent().has(&ADMIN_COUNT_KEY) {
            env.storage().persistent().extend_ttl(
                &ADMIN_COUNT_KEY,
                PERSISTENT_TTL_THRESHOLD,
                PERSISTENT_EXTEND_TO,
            );
        }

        for signer in admin_signers.iter() {
            let key: SignerKey = signer.clone().into();
            if signer.is_authorized(env, &key, auth_contexts) {
                return Ok(());
            }
        }

        for signer in standard_signers.iter() {
            let key: SignerKey = signer.clone().into();
            if signer.is_authorized(env, &key, auth_contexts) {
                return Ok(());
            }
        }

        Err(Error::InsufficientPermissions)
    }

    pub fn call_plugins_on_auth(env: &Env, auth_contexts: &Vec<Context>) -> Result<(), Error> {
        let skip_plugin = Self::plugin_being_uninstalled(env, auth_contexts);

        let storage = Storage::instance();
        for (plugin, _) in storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap()
            .iter()
        {
            // Escape hatch: skip the plugin being uninstalled so it cannot
            // veto its own removal.
            if let Some(ref target) = skip_plugin {
                if plugin == *target {
                    continue;
                }
            }

            let res = SmartAccountPluginClient::new(env, &plugin)
                .try_on_auth(&env.current_contract_address(), auth_contexts);
            match res {
                // Plugin approved (new-style Ok(()) or old-style void return —
                // both produce Void at the ABI level).
                Ok(Ok(_)) => {}
                // Return value conversion failure (ABI mismatch) — skip.
                Ok(Err(_)) => {
                    env.events().publish(
                        (TOPIC_PLUGIN, &plugin, VERB_AUTH_FAILED),
                        PluginAuthFailedEvent {
                            plugin: plugin.clone(),
                            error: String::from_str(env, "Plugin return type mismatch (skipped)"),
                        },
                    );
                }
                // Plugin explicitly rejected via Err(PluginRejection::Rejected).
                Err(Ok(_)) => {
                    env.events().publish(
                        (TOPIC_PLUGIN, &plugin, VERB_AUTH_FAILED),
                        PluginAuthFailedEvent {
                            plugin: plugin.clone(),
                            error: String::from_str(env, "Plugin rejected authorization"),
                        },
                    );
                    return Err(Error::PluginOnAuthFailed);
                }
                // Old-style rejection: panic_with_error! with a contract error
                // code that doesn't match PluginRejection. Treat as rejection
                // to preserve backwards compatibility with existing plugins.
                Err(Err(InvokeError::Contract(_))) => {
                    env.events().publish(
                        (TOPIC_PLUGIN, &plugin, VERB_AUTH_FAILED),
                        PluginAuthFailedEvent {
                            plugin: plugin.clone(),
                            error: String::from_str(env, "Plugin rejected authorization"),
                        },
                    );
                    return Err(Error::PluginOnAuthFailed);
                }
                // Technical failure: bare panic!, missing function, host trap,
                // budget exhaustion, expired TTL. Non-blocking — skip.
                Err(Err(InvokeError::Abort)) => {
                    env.events().publish(
                        (TOPIC_PLUGIN, &plugin, VERB_AUTH_FAILED),
                        PluginAuthFailedEvent {
                            plugin: plugin.clone(),
                            error: String::from_str(env, "Plugin technical failure (skipped)"),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// If the auth context includes an `uninstall_plugin` call on this
    /// contract, return the address of the plugin being removed so it can
    /// be skipped in the plugin auth loop.
    fn plugin_being_uninstalled(env: &Env, auth_contexts: &Vec<Context>) -> Option<Address> {
        let self_address = env.current_contract_address();
        for context in auth_contexts.iter() {
            if let Context::Contract(ContractContext {
                contract,
                fn_name,
                args,
            }) = context
            {
                if contract == self_address
                    && fn_name == Symbol::new(env, "uninstall_plugin")
                    && args.len() > 0
                {
                    return Address::try_from_val(env, &args.get(0).unwrap()).ok();
                }
            }
        }
        None
    }
}
