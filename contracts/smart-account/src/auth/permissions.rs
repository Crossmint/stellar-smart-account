use soroban_sdk::{
    auth::{Context, ContractContext},
    Env, Symbol, Vec,
};

use smart_account_interfaces::SmartAccountError;
use smart_account_interfaces::{SignerKey, SignerPolicy, SignerRole};

pub trait AuthorizationCheck {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, context: &Vec<Context>) -> bool;
}

pub trait PolicyCallback {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError>;
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
}

impl PolicyCallback for SignerPolicy {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_add(env, signer_key),
            SignerPolicy::TokenTransferPolicy(policy) => policy.on_add(env, signer_key),
        }
    }
    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        match self {
            SignerPolicy::ExternalValidatorPolicy(policy) => policy.on_revoke(env, signer_key),
            SignerPolicy::TokenTransferPolicy(policy) => policy.on_revoke(env, signer_key),
        }
    }
}

// ============================================================================
// Context classification for fine-grained authorization
// ============================================================================

/// Classifies auth contexts to differentiate between admin operations,
/// recovery operations, and external contract calls.
struct ContextClassification {
    /// True if any context targets the current contract with an admin-only function
    /// (add_signer, update_signer, revoke_signer, upgrade, cancel_recovery, etc.)
    has_admin_ops: bool,
    /// True if any context targets schedule_recovery on the current contract
    has_schedule_recovery: bool,
    /// True if any context targets execute_recovery on the current contract
    has_execute_recovery: bool,
    /// True if any context targets an external contract or is a non-contract context
    has_non_self_contexts: bool,
}

fn classify_contexts(env: &Env, contexts: &Vec<Context>) -> ContextClassification {
    let self_addr = env.current_contract_address();
    let schedule_fn = Symbol::new(env, "schedule_recovery");
    let execute_fn = Symbol::new(env, "execute_recovery");

    let mut result = ContextClassification {
        has_admin_ops: false,
        has_schedule_recovery: false,
        has_execute_recovery: false,
        has_non_self_contexts: false,
    };

    for context in contexts.iter() {
        match context {
            Context::Contract(cc) => {
                let ContractContext {
                    contract, fn_name, ..
                } = cc;
                if contract.eq(&self_addr) {
                    if fn_name == schedule_fn {
                        result.has_schedule_recovery = true;
                    } else if fn_name == execute_fn {
                        result.has_execute_recovery = true;
                    } else {
                        // All other self-contract calls are admin ops
                        // (add_signer, update_signer, revoke_signer, upgrade,
                        //  cancel_recovery, install_plugin, etc.)
                        result.has_admin_ops = true;
                    }
                } else {
                    result.has_non_self_contexts = true;
                }
            }
            _ => {
                result.has_non_self_contexts = true;
            }
        }
    }
    result
}

// SignerRole moved to interfaces crate

// Checks if, for a given execution context, the signer is authorized to perform the operation.
// Logic:
// - Admin signers: always authorized for everything.
// - Standard signers: authorized for non-admin external operations (with policy checks).
//   They can also execute recovery operations (execute_recovery).
// - Recovery signers: can ONLY schedule or execute recovery operations on the current contract.
//   They cannot perform direct admin ops or interact with external contracts.
impl AuthorizationCheck for SignerRole {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        let classification = classify_contexts(env, contexts);

        match self {
            SignerRole::Admin => true,

            SignerRole::Standard(policies, expiration) => {
                // Check signer expiration (defense-in-depth; authorizer checks first)
                if *expiration > 0 && env.ledger().timestamp() > *expiration {
                    return false;
                }
                // Standard signers cannot perform admin operations or schedule recovery
                if classification.has_admin_ops || classification.has_schedule_recovery {
                    return false;
                }
                // Standard signers CAN execute_recovery (anyone can execute after delay)
                // For external contexts, check policies
                if classification.has_non_self_contexts {
                    match policies {
                        // No policies = no restrictions (beyond admin check)
                        None => true,
                        // At least one policy must authorize the full transaction
                        Some(policies) => policies
                            .iter()
                            .any(|policy| policy.is_authorized(env, signer_key, contexts)),
                    }
                } else {
                    // Only self-contract execute_recovery contexts remain
                    true
                }
            }

            SignerRole::Recovery(_, _) => {
                // Recovery signers cannot perform admin ops or call external contracts
                if classification.has_admin_ops || classification.has_non_self_contexts {
                    return false;
                }
                // Recovery signers can only schedule_recovery or execute_recovery
                classification.has_schedule_recovery || classification.has_execute_recovery
            }
        }
    }
}
