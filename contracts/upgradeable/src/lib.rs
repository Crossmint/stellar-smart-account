#![no_std]

use soroban_sdk::{
    contracterror, contractevent, panic_with_error, symbol_short, Address, BytesN, Env, FromVal,
    Symbol, Val,
};

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    MigrationNotAllowed = 1100,
    MigrationAlreadyPending = 1110,
}

pub const MIGRATING: Symbol = symbol_short!("MIGRATING");

/// Emitted when a two-phase upgrade begins (WASM swap). The data is the
/// upgrading contract's own address.
#[contractevent(topics = ["UPGRADE_STARTED"], data_format = "single-value")]
#[derive(Clone)]
pub struct UpgradeStartedEvent {
    pub contract: Address,
}

/// Emitted when a two-phase upgrade completes (migration done). The data is the
/// upgraded contract's own address.
#[contractevent(topics = ["UPGRADE_COMPLETED"], data_format = "single-value")]
#[derive(Clone)]
pub struct UpgradeCompletedEvent {
    pub contract: Address,
}

pub trait SmartAccountUpgradeable: SmartAccountUpgradeableAuth {
    fn upgrade(env: &Env, new_wasm_hash: BytesN<32>) {
        Self::_require_auth_upgrade(env);
        enable_migration(env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

pub trait SmartAccountUpgradeableMigratable:
    SmartAccountUpgradeableAuth + SmartAccountUpgradeableMigratableInternal
{
    fn upgrade(e: &soroban_sdk::Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        Self::_require_auth_upgrade(e);
        ensure_no_pending_migration(e);
        enable_migration(e);
        UpgradeStartedEvent {
            contract: e.current_contract_address(),
        }
        .publish(e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    fn migrate(e: &soroban_sdk::Env, migration_data: Self::MigrationData) {
        Self::_require_auth_upgrade(e);
        ensure_can_complete_migration(e);
        Self::_migrate(e, &migration_data);
        complete_migration(e);
        UpgradeCompletedEvent {
            contract: e.current_contract_address(),
        }
        .publish(e);
    }
}

pub trait SmartAccountUpgradeableMigratableInternal {
    type MigrationData: FromVal<Env, Val>;
    fn _migrate(e: &Env, migration_data: &Self::MigrationData);
}

pub trait SmartAccountUpgradeableAuth {
    fn _require_auth_upgrade(e: &Env);
}

/// Macro to implement SmartAccountUpgradeable for a contract type.
/// This generates the necessary contractimpl block with the upgrade function.
///
/// # Usage
/// ```rust
/// upgradeable::impl_upgradeable!(MyContract);
/// ```
#[macro_export]
macro_rules! impl_upgradeable {
    ($contract_type:ident) => {
        #[soroban_sdk::contractimpl]
        impl SmartAccountUpgradeable for $contract_type {
            fn upgrade(env: &soroban_sdk::Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
                Self::_require_auth_upgrade(env);
                $crate::enable_migration(env);
                env.deployer().update_current_contract_wasm(new_wasm_hash);
            }
        }
    };
}

/// Macro to implement upgradeable-with-migration for a contract type.
/// This generates a `#[contractimpl]` block with both `upgrade` and `migrate` functions,
/// enabling two-phase upgrades: WASM swap followed by data migration.
///
/// The implementing contract must also implement:
/// - `SmartAccountUpgradeableAuth` for authorization
/// - `SmartAccountUpgradeableMigratableInternal` for `_migrate()` logic
///
/// # Usage
/// ```rust
/// upgradeable::impl_upgradeable_migratable!(MyContract, MigrationDataType);
/// ```
#[macro_export]
macro_rules! impl_upgradeable_migratable {
    ($contract_type:ident, $migration_data_type:ty) => {
        #[soroban_sdk::contractimpl]
        impl $contract_type {
            pub fn upgrade(e: &soroban_sdk::Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
                Self::_require_auth_upgrade(e);
                $crate::ensure_no_pending_migration(e);
                $crate::enable_migration(e);
                $crate::UpgradeStartedEvent {
                    contract: e.current_contract_address(),
                }
                .publish(e);
                e.deployer().update_current_contract_wasm(new_wasm_hash);
            }

            pub fn migrate(e: &soroban_sdk::Env, migration_data: $migration_data_type) {
                Self::_require_auth_upgrade(e);
                $crate::ensure_can_complete_migration(e);
                Self::_migrate(e, &migration_data);
                $crate::complete_migration(e);
                $crate::UpgradeCompletedEvent {
                    contract: e.current_contract_address(),
                }
                .publish(e);
            }
        }
    };
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
pub fn ensure_no_pending_migration(e: &Env) {
    if can_complete_migration(e) {
        panic_with_error!(e, Error::MigrationAlreadyPending)
    }
}
pub fn enable_migration(e: &Env) {
    e.storage().instance().set(&MIGRATING, &true);
}

mod test;
