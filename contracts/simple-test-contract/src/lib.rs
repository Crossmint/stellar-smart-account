#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SimpleTestContract;

#[contractimpl]
impl SimpleTestContract {
    pub fn deployed(_env: Env) -> bool {
        true
    }
}
