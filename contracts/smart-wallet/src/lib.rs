#![no_std]

mod auth;
mod error;
mod events;
mod initializable;
mod interface;
mod signer;
mod storage;

use auth::Auth;
use error::Error;
use initializable::Initializable;
use interface::SmartWalletInterface;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    log, panic_with_error, symbol_short, Env, Vec,
};

use crate::{
    signer::{Signatures, SignedPayload, Signer, SignerKey, SignerVal},
    storage::Storage,
};

#[contract]
pub struct SmartWallet;

impl Initializable for SmartWallet {}

#[contractimpl]
impl SmartWalletInterface for SmartWallet {
    fn __constructor(env: Env, signers: Vec<Signer>) {
        let initialize = || {
            if signers.len() == 0 {
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
        let storage = Storage::default();
        let signer_key = signer.clone().into();
        let signer_val = signer.clone().into();
        if storage.get_signer(env, &signer_key).is_some() {
            return Err(Error::SignerAlreadyExists);
        }
        storage.store_signer(env, &signer_key, &signer_val);
        env.events().publish(
            (
                symbol_short!("sw"),
                symbol_short!("add"),
                signer_key.clone(),
            ),
            (signer_val.clone(), signer_val.clone()),
        );
        Ok(())
    }
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        require_auth!(env);
        let storage = Storage::default();
        let signer_key = signer.clone().into();
        let signer_val = signer.clone().into();
        if storage.get_signer(env, &signer_key).is_none() {
            return Err(Error::SignerNotFound);
        }
        storage.update_signer(env, &signer_key, &signer_val);
        env.events().publish(
            (
                symbol_short!("sw"),
                symbol_short!("update"),
                signer_key.clone(),
            ),
            (signer_val.clone(), signer_val.clone()),
        );
        Ok(())
    }
    fn revoke_signer(env: &Env, signer: SignerKey) -> Result<(), Error> {
        require_auth!(env);
        let storage = Storage::default();
        let signer_key = signer.clone();
        if storage.get_signer(env, &signer_key).is_none() {
            return Err(Error::SignerNotFound);
        }
        storage.delete_signer(env, &signer_key);
        Ok(())
    }
    fn get_signer(env: &Env, signer_key: SignerKey) -> Result<Signer, Error> {
        require_auth!(env);
        let storage = Storage::default();
        storage
            .get_signer(env, &signer_key)
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
                    .get_signer(&env, &signer_key)
                    .map_or(false, |signer_val| {
                        let (expiration, limits) = match signer_val {
                            SignerVal::Ed25519(expiration, limits) => (expiration, limits),
                        };
                        Auth::check_signer_is_not_expired(&env, &expiration)
                            .and_then(|_| {
                                Auth::verify_context(
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
                .get_signer(&env, &signer_key)
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
