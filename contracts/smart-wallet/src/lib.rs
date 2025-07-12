#![no_std]

pub mod auth;
pub mod error;
pub mod interface;
pub mod signer;

use crate::auth::signers::SignerVerification as _;
use auth::signer::Signer as _;
use error::Error;
use initializable::{only_not_initialized, Initializable};
use interface::SmartWalletInterface;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    log, panic_with_error, Env, Vec,
};
use storage::Storage;

use crate::{
    auth::signature::AuthorizationPayloads, auth::signer::Signer, auth::signer::SignerKey,
};

#[macro_export]
macro_rules! require_auth {
    ($env:expr) => {
        if Self::is_initialized($env) {
            $env.current_contract_address().require_auth();
        }
    };
}

pub trait SmartWalletAuth {}

#[contract]
pub struct SmartWallet;

pub trait Upgradeable {}

impl Initializable for SmartWallet {}
impl Upgradeable for SmartWallet {}
impl SmartWalletAuth for SmartWallet {}

#[contractimpl]
impl SmartWalletInterface for SmartWallet {
    fn __constructor(env: Env, signers: Vec<Signer>) {
        only_not_initialized!(&env);
        if signers.is_empty() {
            log!(
                &env,
                "No signers provided. At least one signer is required."
            );
            panic_with_error!(env, Error::NoSigners);
        }
        for signer in signers {
            SmartWallet::add_signer(&env, signer).unwrap_or_else(|e| panic_with_error!(env, e));
        }
        SmartWallet::initialize(&env).unwrap_or_else(|e| panic_with_error!(env, e));
    }
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        require_auth!(env);
        Storage::default().store::<SignerKey, Signer>(
            env,
            &signer.clone().into(),
            &signer.clone().into(),
        )?;
        Ok(())
    }
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error> {
        require_auth!(env);
        Storage::default().update::<SignerKey, Signer>(
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
}

#[contractimpl]
impl CustomAccountInterface for SmartWallet {
    type Signature = AuthorizationPayloads;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        auth_payloads: AuthorizationPayloads,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let storage = Storage::default();
        auth_contexts.iter().for_each(|c| {
            log!(&env, "Checking context {:?}", c);
        });
        log!(&env, "Provided auth payloads {:?}", auth_payloads);
        let AuthorizationPayloads(proof_map) = auth_payloads;
        for (signer_key, proof) in proof_map.iter() {
            let signer = match storage.get::<SignerKey, Signer>(&env, &signer_key.clone()) {
                Some(signer) => signer,
                None => {
                    log!(&env, "Signer not found {:?}", signer_key);
                    return Err(Error::SignerNotFound);
                }
            };
            signer.verify(&env, &signature_payload.to_bytes(), &proof)?;
        }
        Ok(())
    }
}

mod test;
mod test_auth;
mod test_utils;
