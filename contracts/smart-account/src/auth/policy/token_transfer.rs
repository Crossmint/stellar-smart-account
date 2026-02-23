use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short, Address, Env, TryFromVal, Vec,
};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyCallback},
    config::{PERSISTENT_EXTEND_TO, PERSISTENT_TTL_THRESHOLD},
};
use smart_account_interfaces::{
    SmartAccountError, SpendTrackerKey, SpendingTracker, TokenTransferPolicy,
};

impl AuthorizationCheck for TokenTransferPolicy {
    fn is_authorized(&self, env: &Env, contexts: &Vec<Context>) -> bool {
        let now = env.ledger().timestamp();

        // 1. Check expiration
        if self.expiration > 0 && now > self.expiration {
            return false;
        }

        // 2. Validate ALL contexts are `transfer` on the specified token
        let mut total_amount: i128 = 0;

        for context in contexts.iter() {
            match context {
                Context::Contract(contract_context) => {
                    let ContractContext {
                        contract,
                        fn_name,
                        args,
                    } = contract_context;

                    // Must be the specific token contract
                    if contract != self.token {
                        return false;
                    }

                    // Must be the "transfer" function
                    if fn_name != symbol_short!("transfer") {
                        return false;
                    }

                    // transfer(from, to, amount): args[0]=from, args[1]=to, args[2]=amount
                    if args.len() < 3 {
                        return false;
                    }

                    // Check recipient allowlist if configured
                    if !self.allowed_recipients.is_empty() {
                        if let Ok(recipient) = Address::try_from_val(env, &args.get(1).unwrap()) {
                            if !self.allowed_recipients.iter().any(|a| a == recipient) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }

                    // Extract transfer amount
                    if let Ok(amount) = i128::try_from_val(env, &args.get(2).unwrap()) {
                        if amount < 0 {
                            return false;
                        }
                        total_amount = total_amount.checked_add(amount).unwrap_or(i128::MAX);
                    } else {
                        return false;
                    }
                }
                _ => {
                    // Non-contract contexts are not allowed
                    return false;
                }
            }
        }

        // 3. Load spending tracker
        let tracker_key = SpendTrackerKey::TokenSpend(self.policy_id.clone());
        let mut tracker: SpendingTracker =
            env.storage()
                .persistent()
                .get(&tracker_key)
                .unwrap_or(SpendingTracker {
                    spent: 0,
                    window_start: now,
                });

        // 4. Check if the spending window should reset
        if self.reset_window_secs > 0
            && now.saturating_sub(tracker.window_start) >= self.reset_window_secs
        {
            tracker.spent = 0;
            tracker.window_start = now;
        }

        // 5. Check cumulative limit
        let new_total = tracker.spent.checked_add(total_amount).unwrap_or(i128::MAX);
        if new_total > self.limit {
            return false;
        }

        // 6. Update spending tracker
        tracker.spent = new_total;
        env.storage().persistent().set(&tracker_key, &tracker);
        env.storage().persistent().extend_ttl(
            &tracker_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );

        true
    }
}

impl PolicyCallback for TokenTransferPolicy {
    fn on_add(&self, env: &Env) -> Result<(), SmartAccountError> {
        // Validate policy parameters
        if self.limit <= 0 {
            return Err(SmartAccountError::InvalidPolicy);
        }

        // If expiration is set, it must be in the future
        if self.expiration > 0 && self.expiration <= env.ledger().timestamp() {
            return Err(SmartAccountError::InvalidNotAfterTime);
        }

        // Initialize spending tracker
        let tracker_key = SpendTrackerKey::TokenSpend(self.policy_id.clone());
        let tracker = SpendingTracker {
            spent: 0,
            window_start: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&tracker_key, &tracker);
        env.storage().persistent().extend_ttl(
            &tracker_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );

        Ok(())
    }

    fn on_revoke(&self, env: &Env) -> Result<(), SmartAccountError> {
        // Clean up spending tracker from storage
        let tracker_key = SpendTrackerKey::TokenSpend(self.policy_id.clone());
        if env.storage().persistent().has(&tracker_key) {
            env.storage().persistent().remove(&tracker_key);
        }
        Ok(())
    }
}
