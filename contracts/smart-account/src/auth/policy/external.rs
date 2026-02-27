use soroban_sdk::{auth::Context, Env, Vec};

use crate::{
    auth::{
        permissions::{AuthorizationCheck, PolicyCallback},
        policy::interface::SmartAccountPolicyClient,
    },
    events::PolicyCallbackFailedEvent,
    handle_nested_result_failure,
};
use smart_account_interfaces::ExternalPolicy;
use smart_account_interfaces::{SignerKey, SmartAccountError};

impl AuthorizationCheck for ExternalPolicy {
    fn is_authorized(&self, env: &Env, _signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        let wallet_address = env.current_contract_address();
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        policy_client.is_authorized(&wallet_address, contexts)
    }
}

impl PolicyCallback for ExternalPolicy {
    fn on_add(&self, env: &Env, _signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        let res = policy_client.try_on_add(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            PolicyCallbackFailedEvent {
                policy_address: self.policy_address.clone(),
            }
            .publish(env);
            return Err(SmartAccountError::PolicyClientInitializationError);
        });
        Ok(())
    }

    fn on_revoke(&self, env: &Env, _signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        let res = policy_client.try_on_revoke(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            PolicyCallbackFailedEvent {
                policy_address: self.policy_address.clone(),
            }
            .publish(env);
        });
        Ok(())
    }
}
