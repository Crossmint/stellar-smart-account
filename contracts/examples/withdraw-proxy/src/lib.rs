#![no_std]
#![allow(clippy::too_many_arguments)]

//! # Withdraw Proxy
//!
//! Atomic withdraw-then-transfer router. In one invocation it pulls `withdraw_amount` out of a
//! Coordinator-managed account back into `caller`, asserts the balance rose by exactly that
//! amount, then transfers `transfer_amount` from `caller` to `recipient` — both moves succeed or
//! the whole transaction reverts.
//!
//! Both sub-calls pass the same `caller`, so the host gathers them under a single authorization
//! tree: one signature covers the root invocation and both legs. The proxy holds no funds and no
//! approvals, so it can never move funds the caller did not authorize.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, token, Address, BytesN,
    Env, Symbol,
};

/// Token precision the proxy supports, asserted on-chain. All amounts are token smallest units.
pub const EXPECTED_DECIMALS: u32 = 7;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `transfer_amount` or `withdraw_amount` was not strictly positive.
    NonPositiveAmount = 1,
    /// The token does not report [`EXPECTED_DECIMALS`] decimals.
    UnsupportedToken = 2,
    /// `caller`'s balance did not increase by exactly `withdraw_amount` after the withdrawal.
    WithdrawAmountMismatch = 3,
}

/// Withdrawal authorization forwarded verbatim to [`Coordinator::withdraw_assets`]; opaque to
/// this proxy.
///
/// NOTE: the byte widths mirror an ed25519 scheme (32-byte key, 32-byte salt, 64-byte signature).
/// Confirm the exact widths and fixed-vs-dynamic encoding against the deployed Coordinator before
/// mainnet use, and adjust this struct and the [`Coordinator`] client to match.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawAuth {
    pub expires_at: u64,
    pub public_key: BytesN<32>,
    pub salt: BytesN<32>,
    pub signature: BytesN<64>,
}

/// Typed view of the Coordinator's withdrawal entrypoint, used to issue the cross-contract call.
#[contractclient(name = "CoordinatorClient")]
pub trait Coordinator {
    fn withdraw_assets(
        env: Env,
        caller: Address,
        collateral: Address,
        asset: Address,
        amount: i128,
        recipient: Address,
        expires_at: u64,
        salt: BytesN<32>,
        signature: BytesN<64>,
        public_key: BytesN<32>,
    );
}

#[contract]
pub struct WithdrawProxy;

#[contractimpl]
impl WithdrawProxy {
    /// Pull `withdraw_amount` of `token` from `collateral` (via `coordinator`) into `caller`,
    /// verify it arrived exactly, then transfer `transfer_amount` from `caller` to `recipient`.
    /// `token` must report [`EXPECTED_DECIMALS`] decimals; all amounts are token smallest units.
    ///
    /// Reverts without moving funds if a guard fails, if `caller`'s balance does not increase by
    /// exactly `withdraw_amount`, if the Coordinator rejects, or if `caller` cannot cover
    /// `transfer_amount`.
    pub fn withdraw_and_transfer(
        env: Env,
        caller: Address,
        coordinator: Address,
        collateral: Address,
        token: Address,
        recipient: Address,
        withdraw_amount: i128,
        transfer_amount: i128,
        auth: WithdrawAuth,
    ) -> Result<(), Error> {
        // One signature covers this invocation and both legs: they share `caller`, so the host
        // presents them under a single authorization tree.
        caller.require_auth();

        if transfer_amount <= 0 || withdraw_amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }

        let token_client = token::Client::new(&env, &token);
        if token_client.decimals() != EXPECTED_DECIMALS {
            return Err(Error::UnsupportedToken);
        }

        let balance_before = token_client.balance(&caller);
        CoordinatorClient::new(&env, &coordinator).withdraw_assets(
            &caller,
            &collateral,
            &token,
            &withdraw_amount,
            &caller,
            &auth.expires_at,
            &auth.salt,
            &auth.signature,
            &auth.public_key,
        );
        // Check the on-ledger balance rather than trusting the Coordinator's reported amount.
        if token_client.balance(&caller) != balance_before + withdraw_amount {
            return Err(Error::WithdrawAmountMismatch);
        }

        token_client.transfer(&caller, &recipient, &transfer_amount);

        env.events().publish(
            (Symbol::new(&env, "withdraw_and_transfer"), caller),
            (recipient, withdraw_amount, transfer_amount),
        );

        Ok(())
    }
}

#[cfg(test)]
mod test;
