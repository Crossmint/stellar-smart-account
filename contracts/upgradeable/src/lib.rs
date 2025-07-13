#![no_std]

use soroban_sdk::{
    contracterror, panic_with_error, symbol_short, BytesN, Env, FromVal, Symbol, Val,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    MigrationNotAllowed = 1100,
}

pub const MIGRATING: Symbol = symbol_short!("MIGRATING");

pub trait SmartWalletUpgradeable: SmartWalletUpgradeableAuth {
    fn upgrade(env: &Env, new_wasm_hash: BytesN<32>) {
        Self::_require_auth_upgrade(env);
        enable_migration(env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

pub trait SmartWalletUpgradeableMigratable:
    SmartWalletUpgradeableAuth + SmartWalletUpgradeableMigratableInternal
{
    fn upgrade(e: &soroban_sdk::Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        Self::_require_auth_upgrade(e);
        enable_migration(e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    fn migrate(e: &soroban_sdk::Env, migration_data: Self::MigrationData) {
        Self::_require_auth_upgrade(e);
        ensure_can_complete_migration(e);
        Self::_migrate(e, &migration_data);
        complete_migration(e);
    }
}

pub trait SmartWalletUpgradeableMigratableInternal {
    type MigrationData: FromVal<Env, Val>;
    fn _migrate(e: &Env, migration_data: &Self::MigrationData);
}

pub trait SmartWalletUpgradeableAuth {
    fn _require_auth_upgrade(e: &Env);
}

pub fn ensure_can_complete_migration(e: &Env) {
    if !can_complete_migration(e) {
        panic_with_error!(e, Error::MigrationNotAllowed)
    }
}
pub fn can_complete_migration(e: &Env) -> bool {
    e.storage()
        .instance()
        .get::<_, bool>(&MIGRATING)
        .unwrap_or(false)
}
pub fn complete_migration(e: &Env) {
    e.storage().instance().set(&MIGRATING, &false);
}
pub fn enable_migration(e: &Env) {
    e.storage().instance().set(&MIGRATING, &true);
}

mod test;
