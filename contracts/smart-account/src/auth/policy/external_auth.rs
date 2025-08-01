use soroban_sdk::{auth::Context, contracttype, vec, Address, Env, IntoVal, Symbol};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyValidator},
    error::Error,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalAuthorizationPolicy {
    pub contract_id: Address,
}

impl AuthorizationCheck for ExternalAuthorizationPolicy {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool {
        match context {
            Context::Contract(contract_context) => env
                .try_invoke_contract::<bool, Error>(
                    &self.contract_id,
                    &Symbol::new(env, "is_authorized"),
                    vec![env, contract_context.clone().into_val(env)],
                )
                .is_ok(),
            _ => false,
        }
    }
}

impl PolicyValidator for ExternalAuthorizationPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        env.try_invoke_contract::<bool, Error>(
            &self.contract_id,
            &Symbol::new(env, "init"),
            vec![env],
        )
        .and_then(|_| Ok(()))
        .map_err(|_| Error::InvalidPolicy)
    }
}
