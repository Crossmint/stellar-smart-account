use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

use crate::{
    auth::{
        permissions::{AuthorizationCheck, PolicyInitiator},
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

impl PolicyInitiator for ExternalPolicy {
    fn init(&self, _env: &Env) -> Result<(), Error> {
        Ok(())
    }
}
