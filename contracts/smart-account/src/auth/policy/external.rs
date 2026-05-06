use soroban_sdk::{auth::Context, Env, Vec};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyCallback},
    config::{TOPIC_POLICY, VERB_CALLBACK_FAILED},
    events::PolicyCallbackFailedEvent,
};
use smart_account_interfaces::{
    ExternalPolicy, SignerKey, SmartAccountError, SmartAccountPolicyClient,
};

/// Authorization check for `ExternalPolicy`. The wallet forwards the
/// evaluating `signer_key` so the external contract can differentiate
/// between signers sharing the same permission contract, and uses
/// `try_is_authorized` to contain panics and ABI mismatches — a malicious
/// or buggy permission contract cannot DoS `__check_auth`.
///
/// `try_*` returns `Result<Result<(), ConversionError>, Result<PolicyError, InvokeError>>`:
///   - `Ok(Ok(()))`         contract returned `Ok(())`         → authorized
///   - `Err(Ok(_))`         contract returned `Err(PolicyError)` or `panic_with_error!` → rejected
///   - `Ok(Err(_))`         ABI conversion error                → fault, log
///   - `Err(Err(_))`        host-level invoke error (panic, TTL) → fault, log
impl AuthorizationCheck for ExternalPolicy {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        let wallet = env.current_contract_address();
        let client = SmartAccountPolicyClient::new(env, &self.policy_address);
        match client.try_is_authorized(&wallet, signer_key, contexts) {
            Ok(Ok(())) => true,
            Err(Ok(_)) => false,
            Ok(Err(_)) | Err(Err(_)) => {
                env.events().publish(
                    (TOPIC_POLICY, VERB_CALLBACK_FAILED),
                    PolicyCallbackFailedEvent {
                        policy_address: self.policy_address.clone(),
                    },
                );
                false
            }
        }
    }
}

impl PolicyCallback for ExternalPolicy {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        let wallet = env.current_contract_address();
        let client = SmartAccountPolicyClient::new(env, &self.policy_address);
        match client.try_on_add(&wallet, signer_key) {
            Ok(Ok(())) => Ok(()),
            _ => {
                env.events().publish(
                    (TOPIC_POLICY, VERB_CALLBACK_FAILED),
                    PolicyCallbackFailedEvent {
                        policy_address: self.policy_address.clone(),
                    },
                );
                Err(SmartAccountError::PolicyClientInitializationError)
            }
        }
    }

    fn on_update(&self, _env: &Env) -> Result<(), SmartAccountError> {
        Ok(())
    }

    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        let wallet = env.current_contract_address();
        let client = SmartAccountPolicyClient::new(env, &self.policy_address);
        match client.try_on_revoke(&wallet, signer_key) {
            Ok(Ok(())) => {}
            // Non-blocking: an admin must always be able to revoke a misbehaving
            // permission contract, even if the external rejects the callback.
            _ => {
                env.events().publish(
                    (TOPIC_POLICY, VERB_CALLBACK_FAILED),
                    PolicyCallbackFailedEvent {
                        policy_address: self.policy_address.clone(),
                    },
                );
            }
        }
        Ok(())
    }
}
