#![no_std]

use soroban_sdk::{contracttype, Env, IntoVal, TryFromVal, Val};

#[derive(Debug)]
pub enum Error {
    NotFound,
    AlreadyExists,
}

#[contracttype]
pub enum StorageType {
    Persistent,
    Instance,
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

    pub fn store<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        if self.has(env, key) {
            return Err(Error::AlreadyExists);
        }
        self.execute_storage_set(env, key, value);
        Ok(())
    }

    pub fn update<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        if !self.has(env, key) {
            return Err(Error::NotFound);
        }
        self.execute_storage_set(env, key, value);
        Ok(())
    }

    pub fn delete<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) -> Result<(), Error> {
        if !self.has(env, key) {
            return Err(Error::NotFound);
        }
        self.execute_storage_remove(env, key);
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
