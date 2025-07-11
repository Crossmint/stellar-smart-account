use soroban_sdk::{symbol_short, Env, Symbol};

use crate::signer::{SignerKey, SignerVal};

const DEFAULT_STORAGE_TYPE: Symbol = symbol_short!("def_stor");

enum StorageType {
    Persistent,
    Instance,
}

pub struct Storage {
    storage_type: StorageType,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Persistent,
        }
    }
}

impl Storage {
    pub fn get_signer(&self, env: &Env, signer: &SignerKey) -> Option<SignerVal> {
        match self.storage_type {
            StorageType::Persistent => env
                .storage()
                .persistent()
                .get::<SignerKey, SignerVal>(signer),
            StorageType::Instance => env.storage().instance().get::<SignerKey, SignerVal>(signer),
        }
    }

    pub fn store_signer(&self, env: &Env, signer_key: &SignerKey, signer: &SignerVal) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage()
                    .persistent()
                    .set::<SignerKey, SignerVal>(signer_key, signer);
            }
            StorageType::Instance => {
                env.storage()
                    .instance()
                    .set::<SignerKey, SignerVal>(signer_key, signer);
            }
        }
    }

    pub fn update_signer(&self, env: &Env, signer_key: &SignerKey, signer: &SignerVal) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage()
                    .persistent()
                    .set::<SignerKey, SignerVal>(signer_key, signer);
            }
            StorageType::Instance => {
                env.storage()
                    .instance()
                    .set::<SignerKey, SignerVal>(signer_key, signer);
            }
        }
    }

    pub fn delete_signer(&self, env: &Env, signer_key: &SignerKey) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage().persistent().remove::<SignerKey>(signer_key);
            }
            StorageType::Instance => {
                env.storage().instance().remove::<SignerKey>(signer_key);
            }
        }
    }
}
