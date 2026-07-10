#![no_std]

use soroban_sdk::{contractevent, contracttype, Env, IntoVal, TryFromVal, Val};

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

/// Emitted when a value is first stored under a key.
///
/// Carries the same `{storage_type, operation}` data body as the update and
/// delete events so the on-chain payload is uniform across storage mutations;
/// the operation is always [`StorageOperation::Store`] here.
#[contractevent(topics = ["storage", "store"])]
#[derive(Clone)]
pub struct StorageStoredEvent {
    pub storage_type: StorageType,
    pub operation: StorageOperation,
}

/// Emitted when an existing value is updated. The operation is always
/// [`StorageOperation::Update`].
#[contractevent(topics = ["storage", "update"])]
#[derive(Clone)]
pub struct StorageUpdatedEvent {
    pub storage_type: StorageType,
    pub operation: StorageOperation,
}

/// Emitted when a value is deleted. The operation is always
/// [`StorageOperation::Delete`].
#[contractevent(topics = ["storage", "delete"])]
#[derive(Clone)]
pub struct StorageDeletedEvent {
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
    pub fn store<K: IntoVal<Env, Val>, V: IntoVal<Env, Val> + TryFromVal<Env, Val> + Clone>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        let result = match self.storage_type {
            StorageType::Persistent => {
                env.storage()
                    .persistent()
                    .try_update(key, |existing: Option<V>| {
                        if existing.is_some() {
                            Err(Error::AlreadyExists)
                        } else {
                            Ok(value.clone())
                        }
                    })
            }
            StorageType::Instance => {
                env.storage()
                    .instance()
                    .try_update(key, |existing: Option<V>| {
                        if existing.is_some() {
                            Err(Error::AlreadyExists)
                        } else {
                            Ok(value.clone())
                        }
                    })
            }
        };

        match result {
            Ok(_) => {
                StorageStoredEvent {
                    storage_type: self.storage_type.clone(),
                    operation: StorageOperation::Store,
                }
                .publish(env);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn update<K: IntoVal<Env, Val>, V: IntoVal<Env, Val> + TryFromVal<Env, Val> + Clone>(
        &self,
        env: &Env,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        let result = match self.storage_type {
            StorageType::Persistent => {
                env.storage()
                    .persistent()
                    .try_update(key, |existing: Option<V>| {
                        if existing.is_none() {
                            Err(Error::NotFound)
                        } else {
                            Ok(value.clone())
                        }
                    })
            }
            StorageType::Instance => {
                env.storage()
                    .instance()
                    .try_update(key, |existing: Option<V>| {
                        if existing.is_none() {
                            Err(Error::NotFound)
                        } else {
                            Ok(value.clone())
                        }
                    })
            }
        };

        match result {
            Ok(_) => {
                StorageUpdatedEvent {
                    storage_type: self.storage_type.clone(),
                    operation: StorageOperation::Update,
                }
                .publish(env);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) -> Result<(), Error> {
        match self.storage_type {
            StorageType::Persistent => {
                if !env.storage().persistent().has::<K>(key) {
                    return Err(Error::NotFound);
                }
                env.storage().persistent().remove::<K>(key);
            }
            StorageType::Instance => {
                if !env.storage().instance().has::<K>(key) {
                    return Err(Error::NotFound);
                }
                env.storage().instance().remove::<K>(key);
            }
        }

        StorageDeletedEvent {
            storage_type: self.storage_type.clone(),
            operation: StorageOperation::Delete,
        }
        .publish(env);

        Ok(())
    }

    pub fn extend_ttl<K: IntoVal<Env, Val>>(
        &self,
        env: &Env,
        key: &K,
        threshold: u32,
        extend_to: u32,
    ) {
        match self.storage_type {
            StorageType::Persistent => {
                env.storage()
                    .persistent()
                    .extend_ttl(key, threshold, extend_to);
            }
            StorageType::Instance => {
                // Instance storage TTL is managed at the instance level, not per-key
            }
        }
    }

    pub fn has<K: IntoVal<Env, Val>>(&self, env: &Env, key: &K) -> bool {
        match self.storage_type {
            StorageType::Persistent => env.storage().persistent().has::<K>(key),
            StorageType::Instance => env.storage().instance().has::<K>(key),
        }
    }
}

mod test;
