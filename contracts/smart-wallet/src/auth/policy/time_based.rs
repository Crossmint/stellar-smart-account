use soroban_sdk::{auth::Context, contracttype, Env};

use crate::{
    auth::permissions::{InitCheck, PermissionsCheck},
    error::Error,
};

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct TimeBasedPolicy {
    pub not_before: u64,
    pub not_after: u64,
}

impl PermissionsCheck for TimeBasedPolicy {
    fn is_authorized(&self, env: &Env, _context: &Context) -> bool {
        let current_time = env.ledger().timestamp();
        current_time >= self.not_before && current_time <= self.not_after
    }
}

impl InitCheck for TimeBasedPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        let current_time = env.ledger().timestamp();
        if self.not_after < current_time {
            return Err(Error::InvalidNotAfterTime);
        }
        if self.not_before > self.not_after {
            return Err(Error::InvalidTimeRange);
        }
        Ok(())
    }
}
