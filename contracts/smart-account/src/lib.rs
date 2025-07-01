#![no_std]
pub mod interface;
pub mod types;

use soroban_sdk::{contract, contractimpl, Env, Vec, auth::{Context, CustomAccountInterface},crypto::Hash};
use interface::SmartAccountInterface;
use types::{Signatures, Error};

#[contract]
pub struct Contract;

#[contractimpl]
impl SmartAccountInterface for Contract {
}

#[contractimpl]
impl CustomAccountInterface for Contract {
    type Error = Error;
    type Signature = Signatures;

    #[allow(non_snake_case)]
    fn __check_auth(
        _env: Env,
        _signature_payload: Hash<32>,
        _signatures: Signatures,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

mod test;
