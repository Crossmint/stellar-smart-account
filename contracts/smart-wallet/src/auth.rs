use crate::{
    error::Error,
    signer::{Signatures, SignerExpiration, SignerKey, SignerLimits},
};
use soroban_sdk::{
    auth::{Context, ContractContext},
    Env, FromVal, Symbol, Vec,
};

#[macro_export]
macro_rules! require_auth {
    ($env:expr) => {
        if Self::is_initialized($env) {
            $env.current_contract_address().require_auth();
        }
    };
}

pub trait SmartWalletAuth {
    fn check_signer_is_not_expired(env: &Env, expiration: &SignerExpiration) -> Result<(), Error> {
        if let SignerExpiration(Some(signer_expiration)) = expiration {
            if env.ledger().sequence() > *signer_expiration {
                return Err(Error::SignerExpired);
            }
        }
        Ok(())
    }
    fn verify_context(
        env: &Env,
        context: &Context,
        signer_key: &SignerKey,
        limits: &SignerLimits,
        signatures: &Signatures,
    ) -> Result<(), Error> {
        if let SignerLimits(Some(signer_limits)) = limits {
            if signer_limits.is_empty() {
                return Ok(());
            }

            let signer_limits_keys = match context {
                Context::Contract(ContractContext {
                    contract,
                    fn_name,
                    args,
                }) => {
                    signer_limits
                        .get(contract.clone())
                        .map_or(None, |signer_limits_keys| {
                            if *contract == env.current_contract_address()
                                && *fn_name != Symbol::new(&env, "remove_signer")
                                || (*fn_name == Symbol::new(&env, "remove_signer")
                                    && SignerKey::from_val(env, &args.get_unchecked(0))
                                        != *signer_key)
                            {
                                return None; // self trying to do something other than remove itself
                            }
                            Some(signer_limits_keys)
                        })
                }
                Context::CreateContractHostFn(_) => {
                    signer_limits.get(env.current_contract_address())
                }
                Context::CreateContractWithCtorHostFn(_) => {
                    signer_limits.get(env.current_contract_address())
                }
            };
            return if let Some(signer_limits_keys) = signer_limits_keys {
                Self::verify_signer_limit_keys(
                    env,
                    signer_key,
                    signatures,
                    &signer_limits_keys,
                    &context,
                )
            } else {
                Err(Error::MatchingSignatureNotFound)
            };
        }
        Ok(())
    }

    fn verify_signer_limit_keys(
        env: &Env,
        signer_key: &SignerKey,
        signatures: &Signatures,
        signer_limits_keys: &Option<Vec<SignerKey>>,
        context: &Context,
    ) -> Result<(), Error> {
        if let Some(signer_limits_keys) = signer_limits_keys {
            for signer_limits_key in signer_limits_keys.iter() {
                if !signatures.0.contains_key(signer_limits_key.clone()) {
                    // if any required key is missing this contract invocation is invalid
                    return Err(Error::MatchingSignatureNotFound);
                }
            }
        }
        Ok(())
    }
}
