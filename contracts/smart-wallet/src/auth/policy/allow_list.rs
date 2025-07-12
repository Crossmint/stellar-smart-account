use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

use crate::{
    auth::permissions::{InitCheck, PermissionsCheck},
    error::Error,
};

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractAllowListPolicy {
    pub allowed_contracts: Vec<Address>,
}

impl PermissionsCheck for ContractAllowListPolicy {
    fn is_authorized(&self, _env: &Env, context: &Context) -> bool {
        match context {
            Context::Contract(contract_context) => {
                self.allowed_contracts.contains(&contract_context.contract)
            }
            _ => false,
        }
    }
}

impl InitCheck for ContractAllowListPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        if self
            .allowed_contracts
            .contains(&env.current_contract_address())
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
