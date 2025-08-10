use soroban_sdk::{
    auth::{Context, ContractContext},
    contracttype, Env, Vec,
};

use crate::{
    auth::policy::{ExternalPolicy, TimeBasedPolicy},
    error::Error,
};

pub trait AuthorizationCheck {
    fn is_authorized(&self, env: &Env, context: &Vec<Context>) -> bool;
}

pub trait PolicyCallback {
    fn on_add(&self, env: &Env) -> Result<(), Error>;
    fn on_revoke(&self, env: &Env) -> Result<(), Error>;
}

// Main policy enum that wraps the individual policies
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    TimeWindowPolicy(TimeBasedPolicy),
    ExternalValidatorPolicy(ExternalPolicy),
}

// Delegate to the specific policy implementation
impl AuthorizationCheck for SignerPolicy {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        match self {
            SignerPolicy::TimeWindowPolicy(policy) => policy.is_authorized(env, contexts),
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.is_authorized(env, contexts),
        }
    }
}

impl PolicyCallback for SignerPolicy {
    fn on_add(&self, env: &Env) -> Result<(), Error> {
        match self {
            SignerPolicy::TimeWindowPolicy(policy) => policy.on_add(env),
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_add(env),
        }
    }
    fn on_revoke(&self, env: &Env) -> Result<(), Error> {
        match self {
            SignerPolicy::TimeWindowPolicy(policy) => policy.on_revoke(env),
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_revoke(env),
        }
    }
}

// This defines the roles that a configured signer can have
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    // Can authorize any operation, including changing signers and upgrading the contract
    Admin,
    // Can authorize any operation, except changing signers and upgrading the contract, subject
    // to the restrictions specified in the policies (if any).
    Standard(Vec<SignerPolicy>),
}

// Checks if, for a given execution context, the signer is authorized to perform the operation.
// Logic:
// If it's an admin signer, it's authorized.
// If it's a standard signer, it's authorized if the operation is not a administration operation.
// If it's a restricted signer, it's authorized if all the policies are authorized.
impl AuthorizationCheck for SignerRole {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        let needs_admin_approval = contexts.iter().any(|context| match context {
            Context::Contract(context) => {
                let ContractContext { contract, .. } = context;
                contract.eq(&env.current_contract_address())
            }
            _ => false,
        });

        match self {
            SignerRole::Admin => true,
            SignerRole::Standard(policies) => {
                // Standard signers cannot perform admin operations
                if needs_admin_approval {
                    false
                } else {
                    // If not an admin operation, check all policies (if any)
                    policies
                        .iter()
                        .all(|policy| policy.is_authorized(env, contexts))
                }
            }
        }
    }
}

//
