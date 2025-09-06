use soroban_sdk::{auth::Context, Env, Vec};

use crate::{
    auth::{
        permissions::{AuthorizationCheck, PolicyCallback},
        policy::interface::SmartAccountPolicyClient,
    },
    config::{TOPIC_POLICY, VERB_CALLBACK_FAILED},
    events::PolicyCallbackFailedEvent,
    handle_nested_result_failure,
};
use smart_account_interfaces::ExternalPolicy;
use smart_account_interfaces::SmartAccountError;

impl AuthorizationCheck for ExternalPolicy {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        let wallet_address = env.current_contract_address();
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        policy_client.is_authorized(&wallet_address, contexts)
    }
}

impl PolicyCallback for ExternalPolicy {
    fn on_add(&self, env: &Env) -> Result<(), SmartAccountError> {
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        let res = policy_client.try_on_add(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            // Emit event indicating that the on_add callback failed
            env.events().publish(
                (TOPIC_POLICY, VERB_CALLBACK_FAILED),
                PolicyCallbackFailedEvent {
                    policy_address: self.policy_address.clone(),
                },
            );
            return Err(SmartAccountError::PolicyClientInitializationError);
        });
        Ok(())
    }

    fn on_revoke(&self, env: &Env) -> Result<(), SmartAccountError> {
        let policy_client = SmartAccountPolicyClient::new(env, &self.policy_address);
        let res = policy_client.try_on_revoke(&env.current_contract_address());
        handle_nested_result_failure!(res, {
            // Emit event indicating that the on_revoke callback failed
            env.events().publish(
                (TOPIC_POLICY, VERB_CALLBACK_FAILED),
                PolicyCallbackFailedEvent {
                    policy_address: self.policy_address.clone(),
                },
            );
        });
        Ok(())
    }
}
