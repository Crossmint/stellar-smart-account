/// Authorization service that verifies proofs and enforces role/policy checks.
use crate::auth::permissions::{AuthorizationCheck, SignerRole};
use crate::auth::proof::SignatureProofs;
use crate::auth::signer::{Signer, SignerKey};
use crate::auth::signers::SignatureVerifier as _;
use crate::config::{PLUGINS_KEY, TOPIC_PLUGIN, VERB_AUTH_FAILED};
use crate::error::Error;
use crate::events::PluginAuthFailedEvent;
use crate::handle_nested_result_failure;
use smart_account_interfaces::SmartAccountPluginClient;
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
            signer.verify(env, &signature_payload.to_bytes(), &proof)?;

            match signer.role() {
                SignerRole::Admin => admin_signers.push_back(signer),
                SignerRole::Standard(_) => standard_signers.push_back(signer),
            }
        }

        for signer in admin_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
                return Ok(());
            }
        }

        for signer in standard_signers.iter() {
            if signer.is_authorized(env, auth_contexts) {
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
            handle_nested_result_failure!(res, {
                env.events().publish(
                    (TOPIC_PLUGIN, &plugin, VERB_AUTH_FAILED),
                    PluginAuthFailedEvent {
                        plugin: plugin.clone(),
                        error: String::from_str(env, "Plugin on_auth failed"),
                    },
                );
                return Err(Error::PluginOnAuthFailed);
            });
        }
        Ok(())
    }
}
