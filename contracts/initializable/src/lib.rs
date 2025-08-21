#![no_std]

use soroban_sdk::{contracterror, symbol_short, Env, Symbol};

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 0,
    NotInitialized = 1,
}

const INITIALIZED: Symbol = symbol_short!("INIT");

/// Macro to ensure a function only runs if the contract is initialized
/// Usage: only_initialized!(env);
/// This should be called at the beginning of functions that require initialization
#[macro_export]
macro_rules! only_initialized {
    ($env:expr) => {
        if !Self::is_initialized($env) {
            panic_with_error!($env, Error::NotInitialized);
        }
    };
}

/// Macro to ensure a function only runs if the contract is initialized
/// Usage: only_initialized!(env);
/// This should be called at the beginning of functions that require initialization
#[macro_export]
macro_rules! only_not_initialized {
    ($env:expr) => {
        if Self::is_initialized($env) {
            panic_with_error!($env, Error::AlreadyInitialized);
        }
    };
}

pub trait Initializable {
    fn get_initialization_value(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<Symbol, bool>(&INITIALIZED)
            .unwrap_or(false)
    }

    fn set_initialization_value(env: &Env, value: bool) {
        env.storage()
            .instance()
            .set::<Symbol, bool>(&INITIALIZED, &value);
    }

    fn ensure_not_initialized(env: &Env) -> Result<(), Error> {
        if Self::get_initialization_value(env) {
            return Err(Error::AlreadyInitialized);
        }
        Ok(())
    }

    fn ensure_initialized(env: &Env) -> Result<(), Error> {
        if !Self::get_initialization_value(env) {
            return Err(Error::NotInitialized);
        }
        Ok(())
    }

    fn mark_initialized(env: &Env) -> Result<(), Error> {
        if Self::get_initialization_value(env) {
            return Err(Error::AlreadyInitialized);
        }
        Self::set_initialization_value(env, true);
        env.events().publish(
            (Symbol::new(env, "INITIALIZED"),),
            env.current_contract_address(),
        );
        Ok(())
    }

    fn is_initialized(env: &Env) -> bool {
        Self::get_initialization_value(env)
    }

    fn initialize(env: &Env) -> Result<(), Error> {
        Self::ensure_not_initialized(env)?;
        Self::mark_initialized(env)?;
        Self::ensure_initialized(env)?;
        Ok(())
    }
}

mod test;
