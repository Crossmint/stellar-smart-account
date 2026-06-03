#![no_std]
#![allow(clippy::too_many_arguments)]

//! # Withdraw Proxy
//!
//! Atomic "pull-from-collateral-and-send" router for Rain card collateral on Stellar.
//!
//! A Crossmint smart wallet can hold a token both directly and as collateral backing a Rain
//! card. This contract lets a SINGLE atomic transaction fund a transfer from BOTH sources: it
//! pulls a portion out of the Rain collateral (via the Rain Coordinator) back INTO the wallet,
//! verifies the wallet received exactly that amount, then sends the recipient's payment from the
//! wallet.
//!
//! ## Flow
//!
//! 1. `coordinator.withdraw_assets(caller = wallet, …, recipient = wallet, withdraw_amount)` —
//!    the collateral is returned to the **wallet itself** (Rain's signature only ever authorizes
//!    returning collateral to its owner, never to a third party).
//! 2. Assert `balance(wallet)` increased by **exactly** `withdraw_amount` — so a buggy or
//!    malicious Coordinator that moved nothing, or the wrong amount, reverts the whole tx.
//! 3. `token.transfer(from = wallet, to = recipient, transfer_amount)` — the recipient gets one
//!    clean transfer from the wallet.
//!
//! ## Why a proxy is needed
//!
//! The Crossmint Stellar smart account is auth-only (it implements `__check_auth` but has no
//! `execute`/batch entrypoint), and a Stellar transaction carries a single `InvokeHostFunction`
//! operation. So the wallet cannot itself be the root that dispatches two contract calls. This
//! proxy is that root: both sub-calls pass the SAME `caller` (the wallet), so the host presents
//! both to the wallet's `__check_auth` together — ONE wallet signature authorizes the whole
//! bundle, and it is atomic (the recipient is paid in full or nothing moves).
//!
//! ## Token & units
//!
//! The token is a parameter, not hard-coded — but the contract asserts it reports
//! [`EXPECTED_DECIMALS`] (7), the Stellar USDC precision, so the raw amounts here line up with
//! the cents→smallest-units conversion the caller does off-chain (Rain's API speaks cents).
//! Every `*_amount` is a token SMALLEST UNIT; the contract performs no conversion.
//!
//! ## Trust
//!
//! The proxy holds no funds and no approvals, and can never move a wallet's funds on its own:
//! both legs require the wallet's own authorization (`require_auth(caller)`), the collateral leg
//! additionally requires Rain's detached co-signature (in [`WithdrawAuth`], verified inside the
//! Coordinator), and the balance assertion means the proxy never trusts the Coordinator's word
//! for the withdrawn amount.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, token, Address, BytesN,
    Env, Symbol,
};

/// Token precision the proxy is built for (Stellar USDC = 7 decimals). Asserted on-chain so the
/// raw amounts match the caller's off-chain cents→smallest-units conversion.
pub const EXPECTED_DECIMALS: u32 = 7;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `transfer_amount` or `withdraw_amount` was not strictly positive. This proxy exists for
    /// the split case (both wallet and collateral contribute); a zero leg means the caller
    /// should use a plain transfer or a single `withdraw_assets` call instead.
    NonPositiveAmount = 1,
    /// The token does not report [`EXPECTED_DECIMALS`] decimals.
    UnsupportedToken = 2,
    /// The wallet's balance did not increase by exactly `withdraw_amount` after the withdrawal —
    /// the Coordinator did not deliver what was requested. The whole transaction reverts.
    WithdrawAmountMismatch = 3,
}

/// Rain's withdrawal authorization, as returned by the Rain withdrawal-signature API and
/// verified inside the Coordinator. These fields are opaque to this proxy — it only forwards
/// them to [`Coordinator::withdraw_assets`].
///
/// NOTE: the byte widths below mirror an ed25519 scheme (32-byte key, 32-byte salt, 64-byte
/// signature). The published SignifyHQ example passes these as dynamic `Bytes`; confirm the
/// exact widths and dynamic-vs-fixed encoding against the deployed Rain Coordinator before
/// mainnet use, and adjust both this struct and the [`Coordinator`] client to match.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawAuth {
    pub expires_at: u64,
    pub public_key: BytesN<32>,
    pub salt: BytesN<32>,
    pub signature: BytesN<64>,
}

/// Minimal view of the Rain Coordinator contract's withdrawal entrypoint, used only to issue a
/// typed cross-contract call. The Coordinator verifies Rain's detached signature in-contract and
/// enforces `caller == the collateral's registered owner`, then releases `amount` of `asset`
/// from `collateral` to `recipient`.
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
    /// Atomically pull `withdraw_amount` of `token` out of the Rain `collateral` (via
    /// `coordinator`) back into the wallet, verify it arrived exactly, then send
    /// `transfer_amount` from the wallet to `recipient`.
    ///
    /// `caller` is the collateral owner (the user's wallet) and the withdrawal recipient.
    /// `token` is both the withdrawn asset and the transferred token; it must report
    /// [`EXPECTED_DECIMALS`] decimals. All amounts are token SMALLEST UNITS.
    ///
    /// Reverts (nothing moves) if a guard fails, if the wallet's balance does not increase by
    /// exactly `withdraw_amount`, if the Coordinator rejects, or if the wallet cannot cover
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
        // Authenticate the wallet up front. Both sub-calls below additionally re-check
        // `require_auth(caller)`, so a single wallet signature covers this invocation and both
        // legs; an attacker cannot drive funds out of a wallet that did not authorize.
        caller.require_auth();

        if transfer_amount <= 0 || withdraw_amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }

        let token_client = token::Client::new(&env, &token);
        if token_client.decimals() != EXPECTED_DECIMALS {
            return Err(Error::UnsupportedToken);
        }

        // Leg 1 — pull the shortfall out of Rain collateral back into the wallet (recipient =
        // caller). The Coordinator verifies Rain's detached co-signature (`auth`).
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
        // Verify the Coordinator delivered exactly what was requested. If not, revert everything
        // — we never trust the Coordinator's word for the amount.
        if token_client.balance(&caller) != balance_before + withdraw_amount {
            return Err(Error::WithdrawAmountMismatch);
        }

        // Leg 2 — send the recipient's payment from the wallet.
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
