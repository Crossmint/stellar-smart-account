use soroban_sdk::{contracttype, panic_with_error, Env};

use crate::config::{CONTRACT_VERSION_KEY, CURRENT_CONTRACT_VERSION};
use crate::error::Error;

pub mod v1_to_v2;
pub mod v1_types;

use v1_to_v2::{migrate_v1_to_v2, V1ToV2MigrationData};

/// Versioned migration data enum.
///
/// Each variant carries the data needed for a specific version upgrade.
/// The `migrate` entry point accepts this enum and uses the stored
/// `CONTRACT_VERSION` to determine which upgrade path to execute.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MigrationData {
    V1ToV2(V1ToV2MigrationData),
}

/// Reads the current contract version from instance storage.
/// Returns 1 if no version has been stored (pre-v2 contracts).
pub fn get_contract_version(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&CONTRACT_VERSION_KEY)
        .unwrap_or(1)
}

/// Sets the contract version in instance storage.
pub fn set_contract_version(env: &Env, version: u32) {
    env.storage()
        .instance()
        .set(&CONTRACT_VERSION_KEY, &version);
}

/// Version-aware migration dispatcher.
///
/// Reads the current stored version (defaulting to 1 for legacy contracts),
/// validates the migration data matches the expected upgrade path, runs the
/// migration, and bumps the version to `CURRENT_CONTRACT_VERSION`.
pub fn run_migration(env: &Env, data: &MigrationData) {
    let version = get_contract_version(env);

    match (version, data) {
        (1, MigrationData::V1ToV2(v1_data)) => {
            migrate_v1_to_v2(env, v1_data);
        }
        _ => panic_with_error!(env, Error::MigrationVersionMismatch),
    }

    set_contract_version(env, CURRENT_CONTRACT_VERSION);
}
