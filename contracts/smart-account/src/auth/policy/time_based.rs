use soroban_sdk::{auth::Context, contracttype, symbol_short, Env};

use crate::{
    auth::permissions::{AuthorizationCheck, PolicyValidator},
    error::Error,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TimeBasedPolicy {
    pub not_before: u64,
    pub not_after: u64,
}

impl AuthorizationCheck for TimeBasedPolicy {
    fn is_authorized(&self, env: &Env, _context: &Context) -> bool {
        let current_time = env.ledger().timestamp();
        current_time >= self.not_before && current_time <= self.not_after
    }
}

impl PolicyValidator for TimeBasedPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        let current_time = env.ledger().timestamp();
        if self.not_after < current_time {
            env.events().publish(
                (symbol_short!("policy"), symbol_short!("failed")),
                crate::account::PolicyValidationFailedEvent {
                    policy_type: soroban_sdk::String::from_str(env, "time_based"),
                    error_code: 10,
                    error_message: soroban_sdk::String::from_str(env, "InvalidNotAfterTime"),
                    signer_key: None,
                },
            );
            return Err(Error::InvalidNotAfterTime);
        }
        if self.not_before > self.not_after {
            env.events().publish(
                (symbol_short!("policy"), symbol_short!("failed")),
                crate::account::PolicyValidationFailedEvent {
                    policy_type: soroban_sdk::String::from_str(env, "time_based"),
                    error_code: 11,
                    error_message: soroban_sdk::String::from_str(env, "InvalidTimeRange"),
                    signer_key: None,
                },
            );
            return Err(Error::InvalidTimeRange);
        }
        Ok(())
    }
}
