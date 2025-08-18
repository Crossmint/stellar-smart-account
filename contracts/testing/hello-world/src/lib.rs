#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, vec, Address, Env, String, Vec};

#[contract]
pub struct Contract;

// This is a sample contract. Replace this placeholder with your own contract logic.
// A corresponding test example is available in `test.rs`.
//
// For comprehensive examples, visit <https://github.com/stellar/soroban-examples>.
// The repository includes use cases for the Stellar ecosystem, such as data storage on
// the blockchain, token swaps, liquidity pools, and more.
//
// Refer to the official documentation:
// <https://developers.stellar.org/docs/build/smart-contracts/overview>.

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    CustomContractError = 0,
}

#[contractimpl]
impl Contract {
    pub fn hello(env: Env, to: String) -> Vec<String> {
        vec![&env, String::from_str(&env, "Hello"), to]
    }

    pub fn hello_requires_auth(env: Env, caller: Address) -> Vec<String> {
        caller.require_auth();
        vec![&env, String::from_str(&env, "Hello"), caller.to_string()]
    }

    pub fn hello_requires_two_auths(env: Env, caller: Address, caller2: Address) -> Vec<String> {
        caller.require_auth();
        caller2.require_auth();
        vec![
            &env,
            String::from_str(&env, "Hello"),
            caller.to_string(),
            caller2.to_string(),
        ]
    }

    pub fn hello_reverts(_env: Env) -> Result<Vec<String>, Error> {
        Err(Error::CustomContractError)
    }
}

mod test;
