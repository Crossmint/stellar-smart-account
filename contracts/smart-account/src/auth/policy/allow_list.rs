use soroban_sdk::{auth::Context, contracttype, symbol_short, Address, Env, Vec};

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
            env.events().publish(
                (symbol_short!("policy"), symbol_short!("failed")),
                crate::account::PolicyValidationFailedEvent {
                    policy_type: soroban_sdk::String::from_str(env, "contract_allow_list"),
                    error_code: 9,
                    error_message: soroban_sdk::String::from_str(env, "InvalidPolicy"),
                    signer_key: None,
                },
            );
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
