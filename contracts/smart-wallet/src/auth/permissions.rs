use soroban_sdk::{
    auth::{Context, ContractContext},
    contracttype, Env, Vec,
};

use crate::{
    auth::policy::{ContractAllowListPolicy, ContractDenyListPolicy, TimeBasedPolicy},
    error::Error,
};

pub trait AuthorizationCheck {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool;
}

pub trait PolicyValidator {
    fn check(&self, env: &Env) -> Result<(), Error>;
}

// Main policy enum that wraps the individual policies
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    TimeBased(TimeBasedPolicy),
    ContractDenyList(ContractDenyListPolicy),
    ContractAllowList(ContractAllowListPolicy),
}

// Delegate to the specific policy implementation
impl AuthorizationCheck for SignerPolicy {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool {
        match self {
            SignerPolicy::TimeBased(policy) => policy.is_authorized(env, context),
            SignerPolicy::ContractDenyList(policy) => policy.is_authorized(env, context),
            SignerPolicy::ContractAllowList(policy) => policy.is_authorized(env, context),
        }
    }
}

impl PolicyValidator for SignerPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        match self {
            SignerPolicy::TimeBased(policy) => policy.check(env),
            SignerPolicy::ContractDenyList(policy) => policy.check(env),
            SignerPolicy::ContractAllowList(policy) => policy.check(env),
        }
    }
}

// This defines the roles that a configured signer can have
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    // Can authorize any operation, including changing signers and upgrading the contract
    Admin,
    // Can authorize any operation, except changing signers and upgrading the contract
    Standard,
    // Can authorize any operation, except changing signers and upgrading the contract, subject
    // to the restrictions specified in the policies.
    Restricted(Vec<SignerPolicy>),
}

// Checks if, for a given execution context, the signer is authorized to perform the operation.
// Logic:
// If it's an admin signer, it's authorized.
// If it's a standard signer, it's authorized if the operation is not a administration operation.
// If it's a restricted signer, it's authorized if all the policies are authorized.
impl AuthorizationCheck for SignerRole {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool {
        match self {
            SignerRole::Admin => true,
            SignerRole::Standard => match context {
                Context::Contract(context) => {
                    let ContractContext { contract, .. } = context;
                    contract.eq(&env.current_contract_address())
                }
                _ => true,
            },
            SignerRole::Restricted(policies) => policies
                .iter()
                .all(|policy| policy.is_authorized(env, context)),
        }
    }
}

//
