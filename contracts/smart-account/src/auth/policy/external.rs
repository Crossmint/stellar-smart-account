use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

use crate::{
    auth::{
        permissions::{AuthorizationCheck, PolicyCallback},
        policy::interface::SmartAccountPolicyClient,
    },
    error::Error,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPolicy {
    pub policy_address: Address,
}

impl AuthorizationCheck for ExternalPolicy {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        let wallet_address = env.current_contract_address();
        let policy_client = SmartAccountPolicyClient::new(&env, &self.policy_address);
        policy_client.is_authorized(&wallet_address, contexts)
    }
}

impl PolicyCallback for ExternalPolicy {
    fn on_add(&self, env: &Env) -> Result<(), Error> {
        let policy_client = SmartAccountPolicyClient::new(&env, &self.policy_address);
        let _ = policy_client.try_on_add(&env.current_contract_address());
        Ok(())
    }

    fn on_revoke(&self, env: &Env) -> Result<(), Error> {
        let policy_client = SmartAccountPolicyClient::new(&env, &self.policy_address);
        let _ = policy_client.try_on_revoke(&env.current_contract_address());
        Ok(())
    }
}
