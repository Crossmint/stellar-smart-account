#![no_std]

mod auth;
mod error;
mod interface;
mod signer;

use auth::SmartWalletAuth;
use error::Error;
use initializable::{only_not_initialized, Initializable};
use interface::SmartWalletInterface;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    log, panic_with_error, symbol_short, Env, Vec,
};
use storage::Storage;

use crate::signer::{Signatures, SignedPayload, Signer, SignerKey, SignerVal};

#[contract]
pub struct SmartWallet;

pub trait Upgradeable {}

impl Initializable for SmartWallet {}
impl Upgradeable for SmartWallet {}
impl SmartWalletAuth for SmartWallet {}

#[contractimpl]
impl SmartWalletInterface for SmartWallet {
    fn __constructor(env: Env, signers: Vec<Signer>) {
        let initialize = || {
            only_not_initialized!(&env);
            if signers.len() == 0 {
                log!(
                    &env,
                    "No signers provided. At least one signer is required."
                );
                return Err(Error::NoSigners);
            }
            for signer in signers {
                SmartWallet::add_signer(&env, signer)?
            }
            SmartWallet::initialize(&env)?;
            Ok(())
        };
        initialize().unwrap_or_else(|e| panic_with_error!(env, e));
    }
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        require_auth!(env);
        Storage::default().store::<SignerKey, SignerVal>(
            env,
            &signer.clone().into(),
            &signer.clone().into(),
        )?;
        Ok(())
    }
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        require_auth!(env);
        Storage::default().update::<SignerKey, SignerVal>(
            env,
            &signer.clone().into(),
            &signer.clone().into(),
        )?;
        Ok(())
    }
    fn revoke_signer(env: &Env, signer_key: SignerKey) -> Result<(), Error> {
        require_auth!(env);
        Storage::default().delete::<SignerKey>(env, &signer_key)?;
        Ok(())
    }
    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, Error> {
        Storage::default()
            .get::<SignerKey, SignerVal>(env, &signer_key)
            .map(|signer_val| Signer::from((signer_key, signer_val)))
            .ok_or(Error::SignerNotFound)
    }
}

#[contractimpl]
impl CustomAccountInterface for SmartWallet {
    type Signature = Signatures;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Signatures,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::default();
        for context in auth_contexts.iter() {
            log!(&env, "Checking context {:?}", context);
            let has_valid_signer = signatures.0.iter().any(|(signer_key, _)| {
                storage
                    .get::<SignerKey, SignerVal>(&env, &signer_key)
                    .map_or(false, |signer_val| {
                        let (expiration, limits) = match signer_val {
                            SignerVal::Ed25519(expiration, limits) => (expiration, limits),
                        };
                        Self::check_signer_is_not_expired(&env, &expiration)
                            .and_then(|_| {
                                Self::verify_context(
                                    &env,
                                    &context,
                                    &signer_key,
                                    &limits,
                                    &signatures,
                                )
                            })
                            .is_ok()
                    })
            });

            if !has_valid_signer {
                return Err(Error::MatchingSignatureNotFound);
            }
        }

        for (signer_key, signature) in signatures.0.iter() {
            log!(&env, "Checking signature {:?}", signature);
            let signer_val = storage
                .get::<SignerKey, SignerVal>(&env, &signer_key)
                .ok_or(Error::MatchingSignatureNotFound)?;
            log!(&env, "Checking signer {:?}", signer_val);
            Signer::from((signer_key, signer_val)).verify(
                &env,
                &SignedPayload {
                    signature_payload: signature_payload.clone(),
                    signature: signature.clone(),
                },
            )?;
        }
        Ok(())
    }
}

mod test;
