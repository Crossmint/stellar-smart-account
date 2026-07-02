use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short, Address, Env, TryFromVal, Vec,
};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyCallback},
    config::{DAY_IN_LEDGERS, PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD},
};
use smart_account_interfaces::{
    SignerKey, SmartAccountError, SpendTrackerKey, SpendingTracker, TokenTransferPolicy,
};

/// Computes the TTL extend_to value for a spending tracker.
/// Ensures the tracker stays live for at least one full spending window.
fn tracker_extend_to(reset_window_secs: u64) -> u32 {
    if reset_window_secs > 0 {
        let secs_per_ledger = 86400 / DAY_IN_LEDGERS as u64;
        let window_ledgers = (reset_window_secs / secs_per_ledger) as u32 + DAY_IN_LEDGERS;
        window_ledgers.max(PERSISTENT_EXTEND_TO)
    } else {
        PERSISTENT_EXTEND_TO
    }
}

/// Extracts the total transfer amount from a set of contexts, returning None
/// if any context is invalid for this policy.
fn extract_transfer_total(
    policy: &TokenTransferPolicy,
    env: &Env,
    contexts: &Vec<Context>,
) -> Option<i128> {
    let mut total_amount: i128 = 0;

    for context in contexts.iter() {
        match context {
            Context::Contract(contract_context) => {
                let ContractContext {
                    contract,
                    fn_name,
                    args,
                } = contract_context;

                if contract != policy.token {
                    return None;
                }
                if fn_name != symbol_short!("transfer") {
                    return None;
                }
                if args.len() != 3 {
                    return None;
                }

                // Check recipient allowlist if configured
                if let Some(recipients) = &policy.allowed_recipients {
                    if let Ok(recipient) = Address::try_from_val(env, &args.get(1).unwrap()) {
                        if !recipients.iter().any(|a| a == recipient) {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }

                // Extract transfer amount
                if let Ok(amount) = i128::try_from_val(env, &args.get(2).unwrap()) {
                    if amount < 0 {
                        return None;
                    }
                    total_amount = total_amount.checked_add(amount).unwrap_or(i128::MAX);
                } else {
                    return None;
                }
            }
            _ => {
                return None;
            }
        }
    }

    Some(total_amount)
}

/// Loads the spending tracker and computes the proposed new total.
/// Returns None if the new total would exceed the limit.
fn check_spending_limit(
    policy: &TokenTransferPolicy,
    env: &Env,
    signer_key: &SignerKey,
    total_amount: i128,
) -> Option<(SpendTrackerKey, SpendingTracker)> {
    let limit = policy.limit?;
    let now = env.ledger().timestamp();

    let tracker_key = SpendTrackerKey::TokenSpend(policy.policy_id.clone(), signer_key.clone());
    let stored: Option<SpendingTracker> = env.storage().persistent().get(&tracker_key);

    // Refresh the TTL on every check, not just on recorded spends
    if stored.is_some() {
        env.storage().persistent().extend_ttl(
            &tracker_key,
            PERSISTENT_TTL_THRESHOLD,
            tracker_extend_to(policy.reset_window_secs),
        );
    }

    let mut tracker = stored.unwrap_or(SpendingTracker {
        spent: 0,
        window_start: now,
    });

    // Check if the spending window should reset
    if policy.reset_window_secs > 0
        && now.saturating_sub(tracker.window_start) >= policy.reset_window_secs
    {
        tracker.spent = 0;
        tracker.window_start = now;
    }

    let new_total = tracker.spent.checked_add(total_amount).unwrap_or(i128::MAX);
    if new_total > limit {
        return None;
    }

    tracker.spent = new_total;
    Some((tracker_key, tracker))
}

/// Commits the updated spending tracker to persistent storage.
/// TTL is aligned with the configured reset_window_secs so the tracker
/// remains live for at least one full spending window.
fn record_spend(
    reset_window_secs: u64,
    env: &Env,
    tracker_key: &SpendTrackerKey,
    tracker: &SpendingTracker,
) {
    env.storage().persistent().set(tracker_key, tracker);
    env.storage().persistent().extend_ttl(
        tracker_key,
        PERSISTENT_TTL_THRESHOLD,
        tracker_extend_to(reset_window_secs),
    );
}

impl AuthorizationCheck for TokenTransferPolicy {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        // 1. Check expiration
        if self.expiration > 0 && env.ledger().timestamp() > self.expiration {
            return false;
        }

        // 2. Validate contexts and extract total transfer amount
        let total_amount = match extract_transfer_total(self, env, contexts) {
            Some(amount) => amount,
            None => return false,
        };

        // 3. Enforce cumulative spending limit (read-only check)
        if self.limit.is_some()
            && check_spending_limit(self, env, signer_key, total_amount).is_none()
        {
            return false;
        }

        true
    }

    fn on_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) {
        if self.limit.is_none() {
            return;
        }

        let total_amount = match extract_transfer_total(self, env, contexts) {
            Some(amount) => amount,
            None => return,
        };

        if let Some((tracker_key, tracker)) =
            check_spending_limit(self, env, signer_key, total_amount)
        {
            record_spend(self.reset_window_secs, env, &tracker_key, &tracker);
        }
    }
}

fn validate_policy(policy: &TokenTransferPolicy, env: &Env) -> Result<(), SmartAccountError> {
    if let Some(limit) = policy.limit {
        if limit <= 0 {
            return Err(SmartAccountError::InvalidPolicy);
        }
    }
    if policy.expiration > 0 && policy.expiration <= env.ledger().timestamp() {
        return Err(SmartAccountError::InvalidNotAfterTime);
    }
    Ok(())
}

impl PolicyCallback for TokenTransferPolicy {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        validate_policy(self, env)?;

        // Initialize spending tracker if limit is configured
        if self.limit.is_some() {
            let tracker_key =
                SpendTrackerKey::TokenSpend(self.policy_id.clone(), signer_key.clone());
            let tracker = SpendingTracker {
                spent: 0,
                window_start: env.ledger().timestamp(),
            };
            env.storage().persistent().set(&tracker_key, &tracker);
            env.storage().persistent().extend_ttl(
                &tracker_key,
                PERSISTENT_TTL_THRESHOLD,
                tracker_extend_to(self.reset_window_secs),
            );
        }

        Ok(())
    }

    fn on_update(&self, env: &Env) -> Result<(), SmartAccountError> {
        validate_policy(self, env)
    }

    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError> {
        // Clean up spending tracker from storage
        let tracker_key = SpendTrackerKey::TokenSpend(self.policy_id.clone(), signer_key.clone());
        if env.storage().persistent().has(&tracker_key) {
            env.storage().persistent().remove(&tracker_key);
        }
        Ok(())
    }
}
