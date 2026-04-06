use hello_world::HelloContract;
use smart_account::account::SmartAccount;
use smart_account_interfaces::SignerRole;
use soroban_sdk::{
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    vec, Address, Env, IntoVal, String, Symbol, TryIntoVal, Val, Vec,
};

use crate::fee_forwarder::{FeeForwarder, FeeForwarderClient};
use crate::tests::test_utils::Secp256r1TestSigner;

fn setup_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env
}

fn setup_smart_account(env: &Env) -> (Address, Secp256r1TestSigner) {
    let signer = Secp256r1TestSigner::generate(SignerRole::Admin);
    let wallet = env.register(
        SmartAccount,
        (
            vec![env, signer.into_signer(env)],
            Vec::<Address>::new(env),
        ),
    );
    (wallet, signer)
}

fn setup_token(env: &Env, mint_to: &Address, amount: i128) -> Address {
    let admin = Address::generate(env);
    let token_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_sac.address();
    let sac_client = StellarAssetClient::new(env, &token_address);
    sac_client.mint(mint_to, &amount);
    token_address
}

#[test]
fn forward_basic_with_p256_smart_account() {
    let env = setup_env();
    let (wallet, _signer) = setup_smart_account(&env);

    let initial_balance: i128 = 1_000_000;
    let fee_amount: i128 = 100;
    let max_fee_amount: i128 = 200;

    let token_address = setup_token(&env, &wallet, initial_balance);
    let token_client = TokenClient::new(&env, &token_address);

    let forwarder_address = env.register(FeeForwarder, ());
    let forwarder = FeeForwarderClient::new(&env, &forwarder_address);

    let target = env.register(HelloContract, ());
    let relayer = Address::generate(&env);

    let fn_name = Symbol::new(&env, "hello");
    let greeting = String::from_str(&env, "World");
    let fn_args: Vec<Val> = vec![&env, greeting.into_val(&env)];

    let current_ledger = env.ledger().sequence();

    let result: Vec<String> = forwarder
        .forward(
            &token_address,
            &fee_amount,
            &max_fee_amount,
            &(current_ledger + 100),
            &target,
            &fn_name,
            &fn_args,
            &wallet,
            &relayer,
        )
        .try_into_val(&env)
        .unwrap();

    // Verify target function executed correctly
    assert_eq!(result.len(), 2);
    assert_eq!(
        result.get(0).unwrap(),
        String::from_str(&env, "Hello")
    );
    assert_eq!(result.get(1).unwrap(), String::from_str(&env, "World"));

    // Verify fee was transferred from wallet to relayer
    assert_eq!(
        token_client.balance(&wallet),
        initial_balance - fee_amount
    );
    assert_eq!(token_client.balance(&relayer), fee_amount);
}

#[test]
fn forward_with_target_requiring_auth() {
    let env = setup_env();
    let (wallet, _signer) = setup_smart_account(&env);

    let initial_balance: i128 = 1_000_000;
    let fee_amount: i128 = 500;
    let max_fee_amount: i128 = 1_000;

    let token_address = setup_token(&env, &wallet, initial_balance);
    let token_client = TokenClient::new(&env, &token_address);

    let forwarder_address = env.register(FeeForwarder, ());
    let forwarder = FeeForwarderClient::new(&env, &forwarder_address);

    let target = env.register(HelloContract, ());
    let relayer = Address::generate(&env);

    // hello_requires_auth calls caller.require_auth()
    let fn_name = Symbol::new(&env, "hello_requires_auth");
    let fn_args: Vec<Val> = vec![&env, wallet.into_val(&env)];

    let current_ledger = env.ledger().sequence();

    let result: Vec<String> = forwarder
        .forward(
            &token_address,
            &fee_amount,
            &max_fee_amount,
            &(current_ledger + 100),
            &target,
            &fn_name,
            &fn_args,
            &wallet,
            &relayer,
        )
        .try_into_val(&env)
        .unwrap();

    // hello_requires_auth returns ["Hello", <caller.to_string()>]
    assert_eq!(result.len(), 2);
    assert_eq!(
        result.get(0).unwrap(),
        String::from_str(&env, "Hello")
    );

    // Verify fee was transferred
    assert_eq!(
        token_client.balance(&wallet),
        initial_balance - fee_amount
    );
    assert_eq!(token_client.balance(&relayer), fee_amount);
}

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn forward_fails_fee_exceeds_max() {
    let env = setup_env();
    let (wallet, _signer) = setup_smart_account(&env);

    let token_address = setup_token(&env, &wallet, 1_000_000);

    let forwarder_address = env.register(FeeForwarder, ());
    let forwarder = FeeForwarderClient::new(&env, &forwarder_address);

    let target = env.register(HelloContract, ());
    let relayer = Address::generate(&env);

    let fn_name = Symbol::new(&env, "hello");
    let greeting = String::from_str(&env, "World");
    let fn_args: Vec<Val> = vec![&env, greeting.into_val(&env)];

    let current_ledger = env.ledger().sequence();

    // fee_amount (300) > max_fee_amount (200) should panic
    forwarder.forward(
        &token_address,
        &300_i128,
        &200_i128,
        &(current_ledger + 100),
        &target,
        &fn_name,
        &fn_args,
        &wallet,
        &relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn forward_fails_zero_fee() {
    let env = setup_env();
    let (wallet, _signer) = setup_smart_account(&env);

    let token_address = setup_token(&env, &wallet, 1_000_000);

    let forwarder_address = env.register(FeeForwarder, ());
    let forwarder = FeeForwarderClient::new(&env, &forwarder_address);

    let target = env.register(HelloContract, ());
    let relayer = Address::generate(&env);

    let fn_name = Symbol::new(&env, "hello");
    let greeting = String::from_str(&env, "World");
    let fn_args: Vec<Val> = vec![&env, greeting.into_val(&env)];

    let current_ledger = env.ledger().sequence();

    // fee_amount = 0 should panic
    forwarder.forward(
        &token_address,
        &0_i128,
        &200_i128,
        &(current_ledger + 100),
        &target,
        &fn_name,
        &fn_args,
        &wallet,
        &relayer,
    );
}
