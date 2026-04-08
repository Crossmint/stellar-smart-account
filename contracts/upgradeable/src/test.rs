#![cfg(test)]

use soroban_sdk::{contract, contractimpl, Env};

use crate::{complete_migration, enable_migration, ensure_no_pending_migration};

#[contract]
pub struct DummyContract;

#[contractimpl]
impl DummyContract {}

#[test]
#[should_panic(expected = "Error(Contract, #1110)")]
fn test_upgrade_rejected_when_migration_pending() {
    let env = Env::default();
    let contract_id = env.register(DummyContract, ());

    env.as_contract(&contract_id, || {
        enable_migration(&env);
        // A second upgrade attempt while migration is pending must fail.
        ensure_no_pending_migration(&env);
    });
}

#[test]
fn test_upgrade_allowed_after_migration_completes() {
    let env = Env::default();
    let contract_id = env.register(DummyContract, ());

    env.as_contract(&contract_id, || {
        enable_migration(&env);
        complete_migration(&env);
        // After migration completes, another upgrade should be allowed.
        ensure_no_pending_migration(&env);
    });
}
