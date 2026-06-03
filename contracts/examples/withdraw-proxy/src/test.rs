extern crate std;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, BytesN, Env};

use crate::{Error, WithdrawAuth, WithdrawProxy, WithdrawProxyClient};

// Stand-ins for Rain's Coordinator. A real Coordinator verifies Rain's detached signature and
// checks `caller == the collateral's registered owner`; here we just move funds from `collateral`
// to `recipient` (the wallet) so the proxy's effect is observable on-ledger.
//
// Each mock lives in its own module because `#[contractimpl]` emits module-level items keyed by
// the function name, which would otherwise collide between mocks.
mod mock_coordinator {
    use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};

    #[contract]
    pub struct MockCoordinator;

    #[contractimpl]
    impl MockCoordinator {
        pub fn withdraw_assets(
            env: Env,
            caller: Address,
            collateral: Address,
            asset: Address,
            amount: i128,
            recipient: Address,
            _expires_at: u64,
            _salt: BytesN<32>,
            _signature: BytesN<64>,
            _public_key: BytesN<32>,
        ) {
            let _ = caller;
            token::Client::new(&env, &asset).transfer(&collateral, &recipient, &amount);
        }
    }
}

// A Coordinator that always rejects, to prove the whole transaction reverts atomically.
mod failing_coordinator {
    use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

    #[contract]
    pub struct FailingCoordinator;

    #[contractimpl]
    impl FailingCoordinator {
        pub fn withdraw_assets(
            _env: Env,
            _caller: Address,
            _collateral: Address,
            _asset: Address,
            _amount: i128,
            _recipient: Address,
            _expires_at: u64,
            _salt: BytesN<32>,
            _signature: BytesN<64>,
            _public_key: BytesN<32>,
        ) {
            panic!("coordinator rejected the withdrawal");
        }
    }
}

// A Coordinator that "succeeds" but delivers the wrong amount (one more than requested), to prove
// the balance assertion catches it and reverts the (over-)withdrawal.
mod lying_coordinator {
    use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};

    #[contract]
    pub struct LyingCoordinator;

    #[contractimpl]
    impl LyingCoordinator {
        pub fn withdraw_assets(
            env: Env,
            _caller: Address,
            collateral: Address,
            asset: Address,
            amount: i128,
            recipient: Address,
            _expires_at: u64,
            _salt: BytesN<32>,
            _signature: BytesN<64>,
            _public_key: BytesN<32>,
        ) {
            token::Client::new(&env, &asset).transfer(&collateral, &recipient, &(amount + 1));
        }
    }
}

// A token reporting 4 decimals, to prove the proxy rejects non-7-decimal tokens.
mod four_dp_token {
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    pub struct FourDpToken;

    #[contractimpl]
    impl FourDpToken {
        pub fn decimals(_env: Env) -> u32 {
            4
        }
    }
}

use failing_coordinator::FailingCoordinator;
use four_dp_token::FourDpToken;
use lying_coordinator::LyingCoordinator;
use mock_coordinator::MockCoordinator;

fn dummy_auth(env: &Env) -> WithdrawAuth {
    WithdrawAuth {
        expires_at: 0,
        public_key: BytesN::from_array(env, &[7u8; 32]),
        salt: BytesN::from_array(env, &[9u8; 32]),
        signature: BytesN::from_array(env, &[3u8; 64]),
    }
}

struct Harness {
    env: Env,
    proxy_id: Address,
    usdc: Address,
    wallet: Address,
    collateral: Address,
    recipient: Address,
}

fn setup(wallet_balance: i128, collateral_balance: i128) -> Harness {
    let env = Env::default();
    // The mock Coordinators move funds via `token.transfer(from = collateral)`, which requires
    // `collateral`'s auth deep in the call tree (the real Coordinator instead releases collateral
    // on Rain's signature, with no such require_auth). Allow that non-root auth.
    env.mock_all_auths_allowing_non_root_auth();

    // A Stellar Asset Contract reports 7 decimals — matching the proxy's EXPECTED_DECIMALS.
    let sac_admin = Address::generate(&env);
    let usdc = env.register_stellar_asset_contract_v2(sac_admin).address();
    let mint = token::StellarAssetClient::new(&env, &usdc);

    let wallet = Address::generate(&env);
    let collateral = Address::generate(&env);
    let recipient = Address::generate(&env);
    mint.mint(&wallet, &wallet_balance);
    mint.mint(&collateral, &collateral_balance);

    let proxy_id = env.register(WithdrawProxy, ());

    Harness {
        env,
        proxy_id,
        usdc,
        wallet,
        collateral,
        recipient,
    }
}

#[test]
fn funds_recipient_from_both_sources() {
    // Wallet 300 + pull 700 from collateral → wallet holds 1000, then sends 1000 to recipient.
    let h = setup(300, 5_000);
    let coordinator = h.env.register(MockCoordinator, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    proxy.withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &h.usdc,
        &h.recipient,
        &700i128,   // withdrawn into the wallet
        &1_000i128, // sent to the recipient
        &dummy_auth(&h.env),
    );

    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.recipient), 1_000); // one clean transfer
    assert_eq!(token.balance(&h.wallet), 0); // 300 + 700 - 1000
    assert_eq!(token.balance(&h.collateral), 4_300); // 5000 - 700
}

#[test]
fn reverts_atomically_when_transfer_leg_fails() {
    // Wallet 100 + pull 700 = 800, but asked to send 900. The withdraw landed first; the failing
    // transfer must roll the whole transaction back.
    let h = setup(100, 5_000);
    let coordinator = h.env.register(MockCoordinator, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    let res = proxy.try_withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &h.usdc,
        &h.recipient,
        &700i128,
        &900i128,
        &dummy_auth(&h.env),
    );

    assert!(res.is_err());
    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.recipient), 0); // nothing delivered
    assert_eq!(token.balance(&h.collateral), 5_000); // withdraw rolled back
    assert_eq!(token.balance(&h.wallet), 100); // untouched
}

#[test]
fn reverts_atomically_when_coordinator_rejects() {
    let h = setup(300, 5_000);
    let coordinator = h.env.register(FailingCoordinator, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    let res = proxy.try_withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &h.usdc,
        &h.recipient,
        &700i128,
        &1_000i128,
        &dummy_auth(&h.env),
    );

    assert!(res.is_err());
    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.recipient), 0);
    assert_eq!(token.balance(&h.wallet), 300);
    assert_eq!(token.balance(&h.collateral), 5_000);
}

#[test]
fn reverts_when_withdraw_delivers_wrong_amount() {
    // The Coordinator "succeeds" but moves 701 instead of 700. The balance assertion must fail
    // and revert the over-withdrawal — proving the proxy never trusts the Coordinator's word.
    let h = setup(300, 5_000);
    let coordinator = h.env.register(LyingCoordinator, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    let res = proxy.try_withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &h.usdc,
        &h.recipient,
        &700i128,
        &1_000i128,
        &dummy_auth(&h.env),
    );

    assert!(matches!(res, Err(Ok(Error::WithdrawAmountMismatch))));
    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.collateral), 5_000); // over-withdrawal rolled back
    assert_eq!(token.balance(&h.wallet), 300);
    assert_eq!(token.balance(&h.recipient), 0);
}

#[test]
fn rejects_non_positive_amounts() {
    let h = setup(300, 5_000);
    let coordinator = h.env.register(MockCoordinator, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    let res = proxy.try_withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &h.usdc,
        &h.recipient,
        &700i128,
        &0i128, // invalid
        &dummy_auth(&h.env),
    );

    assert!(matches!(res, Err(Ok(Error::NonPositiveAmount))));
    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.recipient), 0);
    assert_eq!(token.balance(&h.collateral), 5_000);
}

#[test]
fn rejects_token_with_unexpected_decimals() {
    let h = setup(300, 5_000);
    let coordinator = h.env.register(MockCoordinator, ());
    let bad_token = h.env.register(FourDpToken, ());
    let proxy = WithdrawProxyClient::new(&h.env, &h.proxy_id);

    let res = proxy.try_withdraw_and_transfer(
        &h.wallet,
        &coordinator,
        &h.collateral,
        &bad_token, // reports 4 decimals
        &h.recipient,
        &700i128,
        &1_000i128,
        &dummy_auth(&h.env),
    );

    assert!(matches!(res, Err(Ok(Error::UnsupportedToken))));
    let token = token::Client::new(&h.env, &h.usdc);
    assert_eq!(token.balance(&h.collateral), 5_000);
    assert_eq!(token.balance(&h.wallet), 300);
}
