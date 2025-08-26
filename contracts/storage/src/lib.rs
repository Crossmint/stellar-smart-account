#![no_std]

use soroban_sdk::{contracttype, symbol_short, Env, IntoVal, TryFromVal, Val};

#[derive(Debug)]
pub enum Error {
    NotFound,
    AlreadyExists,
}

#[contracttype]
#[derive(Clone)]
pub enum StorageType {
    Persistent,
    Instance,
}

#[contracttype]
#[derive(Clone)]
pub enum StorageOperation {
    Store,
    Update,
    Delete,
}

#[contracttype]
#[derive(Clone)]
pub struct StorageChangeEvent {
    pub storage_type: StorageType,
    pub operation: StorageOperation,
}

pub struct Storage {
    storage_type: StorageType,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Instance,
        }
    }
}
impl Storage {
    pub fn instance() -> Self {
        Self {
            storage_type: StorageType::Instance,
        }
    }
    pub fn persistent() -> Self {
        Self {
            storage_type: StorageType::Persistent,
        }
    }
}

impl Storage {
    fn execute_storage_set<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage().persistent().set::<K, V>(key, value);
            }
            StorageType::Instance => {
                env.storage().instance().set::<K, V>(key, value);
            }
        }
    }

    fn execute_storage_remove<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage().persistent().remove::<K>(key);
            }
            StorageType::Instance => {
                env.storage().instance().remove::<K>(key);
            }
        }
    }

    pub fn get<K: IntoVal<Env, Val>, V: TryFromVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
    ) -> Option<V> {
        match self.storage_type {
            StorageType::Persistent => env.storage().persistent().get::<K, V>(key),
            StorageType::Instance => env.storage().instance().get::<K, V>(key),
        }
    }

    /// Store a value in the storage.
    ///
    /// If the key already exists, the operation will fail.
    pub fn store<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        let exists = self.get::<K, Val>(env, key).is_some();
        if exists {
            return Err(Error::AlreadyExists);
        }
        self.execute_storage_set(env, key, value);

        let event = StorageChangeEvent {
            storage_type: self.storage_type.clone(),
            operation: StorageOperation::Store,
        };
        env.events()
            .publish((symbol_short!("storage"), symbol_short!("store")), event);

        Ok(())
    }

    pub fn update<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        let exists = self.get::<K, Val>(env, key).is_some();
        if !exists {
            return Err(Error::NotFound);
        }
        self.execute_storage_set(env, key, value);

        let event = StorageChangeEvent {
            storage_type: self.storage_type.clone(),
            operation: StorageOperation::Update,
        };
        env.events()
            .publish((symbol_short!("storage"), symbol_short!("update")), event);

        Ok(())
    }

    pub fn delete<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) -> Result<(), Error> {
        let exists = match self.storage_type {
            StorageType::Persistent => env.storage().persistent().get::<K, Val>(key).is_some(),
            StorageType::Instance => env.storage().instance().get::<K, Val>(key).is_some(),
        };

        if !exists {
            return Err(Error::NotFound);
        }

        self.execute_storage_remove(env, key);

        let event = StorageChangeEvent {
            storage_type: self.storage_type.clone(),
            operation: StorageOperation::Delete,
        };
        env.events()
            .publish((symbol_short!("storage"), symbol_short!("delete")), event);

        Ok(())
    }

    pub fn has<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) -> bool {
        match self.storage_type {
            StorageType::Persistent => env.storage().persistent().has::<K>(key),
            StorageType::Instance => env.storage().instance().has::<K>(key),
        }
    }
}

mod test;
