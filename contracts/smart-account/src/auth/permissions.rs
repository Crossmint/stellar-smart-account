use soroban_sdk::{
    auth::{Context, ContractContext},
    Env, Vec,
};

use smart_account_interfaces::SmartAccountError;
use smart_account_interfaces::{SignerKey, SignerPolicy, SignerRole};

pub trait AuthorizationCheck {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, context: &Vec<Context>) -> bool;

    /// Called after authorization succeeds to commit any side effects (e.g. spending tracker).
    /// Default is a no-op for policies with no state to commit.
    fn on_authorized(&self, _env: &Env, _signer_key: &SignerKey, _context: &Vec<Context>) {}
}

pub trait PolicyCallback {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError>;
    fn on_update(&self, env: &Env) -> Result<(), SmartAccountError>;
    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError>;
}

// Main policy enum moved to interfaces crate

// Delegate to the specific policy implementation
impl AuthorizationCheck for SignerPolicy {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => {
                policy.is_authorized(env, signer_key, contexts)
            }
            SignerPolicy::TokenTransferPolicy(policy) => {
                policy.is_authorized(env, signer_key, contexts)
            }
        }
    }

    fn on_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => {
                policy.on_authorized(env, signer_key, contexts)
            }
            SignerPolicy::TokenTransferPolicy(policy) => {
                policy.on_authorized(env, signer_key, contexts)
            }
        }
    }
}

impl PolicyCallback for SignerPolicy {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_add(env, signer_key),
            SignerPolicy::TokenTransferPolicy(policy) => policy.on_add(env, signer_key),
        }
    }
    fn on_update(&self, env: &Env) -> Result<(), SmartAccountError> {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_update(env),
            SignerPolicy::TokenTransferPolicy(policy) => policy.on_update(env),
        }
    }
    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_revoke(env, signer_key),
            SignerPolicy::TokenTransferPolicy(policy) => policy.on_revoke(env, signer_key),
        }
    }
}

// SignerRole moved to interfaces crate

// Checks if, for a given execution context, the signer is authorized to perform the operation.
// Logic:
// If it's an admin signer, it's authorized.
// If it's a standard signer, it's authorized if the operation is not a administration operation.
// If it's a restricted signer, it's authorized if all the policies are authorized.
impl AuthorizationCheck for SignerRole {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        let needs_admin_approval = contexts.iter().any(|context| match context {
            Context::Contract(context) => {
                let ContractContext { contract, .. } = context;
                contract.eq(&env.current_contract_address())
            }
            _ => false,
        });

        match self {
            SignerRole::Admin => true,
            SignerRole::Standard(policies, expiration) => {
                // Check signer expiration (defense-in-depth; authorizer checks first)
                if *expiration > 0 && env.ledger().timestamp() > *expiration {
                    return false;
                }
                // Standard signers cannot perform admin operations
                if needs_admin_approval {
                    false
                } else {
                    match policies {
                        // No policies = no restrictions (beyond admin check)
                        None => true,
                        // OR semantics: at least one policy must authorize.
                        // Every matching policy's on_authorized fires so that
                        // overlapping policies (e.g. multiple TokenTransferPolicy
                        // entries on the same token) all commit their state.
                        // Mixed-variant policy sets are rejected at registration
                        // (see SmartAccount::validate_homogeneous_policies).
                        Some(policies) => {
                            let mut authorized = false;
                            for policy in policies.iter() {
                                if policy.is_authorized(env, signer_key, contexts) {
                                    policy.on_authorized(env, signer_key, contexts);
                                    authorized = true;
                                }
                            }
                            authorized
                        }
                    }
                }
            }
        }
    }
}

//
