/// Authorization service that verifies proofs and enforces role/policy checks.
use crate::auth::permissions::AuthorizationCheck;
use crate::auth::proof::SignatureProofs;
use crate::auth::signers::SignatureVerifier as _;
use crate::config::{ADMIN_COUNT_KEY, PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD, PLUGINS_KEY};
use crate::error::Error;
use crate::events::PluginAuthFailedEvent;
use smart_account_interfaces::SmartAccountPluginClient;
use smart_account_interfaces::{Signer, SignerKey, SignerRole};
use soroban_sdk::{auth::Context, crypto::Hash, Env, Vec};
use soroban_sdk::{Address, Map, String, Symbol};
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
        let storage = Storage::instance();
        for (plugin, _) in storage
            .get::<Symbol, Map<Address, ()>>(env, &PLUGINS_KEY)
            .unwrap()
            .iter()
        {
            let res = SmartAccountPluginClient::new(env, &plugin)
                .try_on_auth(&env.current_contract_address(), auth_contexts);
            // Plugin-result classification (Soroban 22 try_* semantics):
            //   Ok(Ok(_))   — plugin returned normally                   → continue
            //   Ok(Err(_))  — return-value ABI decode failure            → SKIP (fail-open)
            //   Err(Ok(_))  — contracterror OR panic!/unwrap/unreachable → REJECT (fail-closed)
            //   Err(Err(_)) — host trap (archival, budget, missing code) → SKIP (fail-open)
            //
            // Note: any `panic!` from the plugin — including an unwrap that
            // fires or an arithmetic overflow — lands in the Err(Ok(_))
            // branch and blocks auth. Only environmental host traps
            // (storage archival, budget exhaustion, stack overflow,
            // contract-not-found) reach Err(Err(_)) and are silently
            // skipped. Plugins that want to stay enforceable should
            // manage their own TTL and avoid unbounded work.
            match res {
                // Plugin executed successfully
                Ok(Ok(_)) => {}
                // Plugin return value ABI decode failure
                // Treat as technical failure: log and continue
                Ok(Err(_)) => {
                    PluginAuthFailedEvent {
                        plugin: plugin.clone(),
                        error: String::from_str(env, "Plugin return type mismatch (skipped)"),
                    }
                    .publish(env);
                }
                // Plugin intentionally rejected (contracterror) or panicked
                // (panic!, panic_with_error!, unwrap, arithmetic overflow, etc.)
                Err(Ok(_)) => {
                    PluginAuthFailedEvent {
                        plugin: plugin.clone(),
                        error: String::from_str(env, "Plugin rejected authorization"),
                    }
                    .publish(env);
                    return Err(Error::PluginOnAuthFailed);
                }
                // Host-level failure: storage archival, budget exhaustion,
                // contract not found, stack overflow. Non-blocking: log
                // and continue to next plugin so an unreachable plugin
                // cannot brick the account.
                Err(Err(_)) => {
                    PluginAuthFailedEvent {
                        plugin: plugin.clone(),
                        error: String::from_str(env, "Plugin technical failure (skipped)"),
                    }
                    .publish(env);
                }
            }
        }
        Ok(())
    }
}
