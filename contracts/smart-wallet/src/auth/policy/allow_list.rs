use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyValidator},
    error::Error,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractAllowListPolicy {
    pub allowed_contracts: Vec<Address>,
}

impl AuthorizationCheck for ContractAllowListPolicy {
    fn is_authorized(&self, _env: &Env, context: &Context) -> bool {
        match context {
            Context::Contract(contract_context) => {
                self.allowed_contracts.contains(&contract_context.contract)
            }
            _ => false,
        }
    }
}

impl PolicyValidator for ContractAllowListPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        if self
            .allowed_contracts
            .contains(env.current_contract_address())
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
