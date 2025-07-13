use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyValidator},
    error::Error,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractDenyListPolicy {
    pub denied_contracts: Vec<Address>,
}

impl AuthorizationCheck for ContractDenyListPolicy {
    fn is_authorized(&self, _env: &Env, context: &Context) -> bool {
        match context {
            Context::Contract(contract_context) => {
                !self.denied_contracts.contains(&contract_context.contract)
            }
            _ => true,
        }
    }
}

impl PolicyValidator for ContractDenyListPolicy {
    fn check(&self, _env: &Env) -> Result<(), Error> {
        Ok(())
    }
}
