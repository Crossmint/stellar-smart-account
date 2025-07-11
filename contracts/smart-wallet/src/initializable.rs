use soroban_sdk::{panic_with_error, symbol_short, Env, Symbol};

use crate::error::Error;

const INITIALIZED: Symbol = symbol_short!("init");

pub trait Initializable {
    fn ensure_not_initialized(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get::<Symbol, bool>(&INITIALIZED)
            .unwrap_or(false)
        {
            return Err(Error::AlreadyInitialized);
        }
        Ok(())
    }

    fn mark_initialized(env: &Env) {
        env.storage()
            .instance()
            .set::<Symbol, bool>(&INITIALIZED, &true);
    }

    fn is_initialized(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<Symbol, bool>(&INITIALIZED)
            .unwrap_or(false)
    }

    fn initialize(env: &Env) -> Result<(), Error> {
        Self::ensure_not_initialized(env)?;
        Self::mark_initialized(env);
        Ok(())
    }
}
