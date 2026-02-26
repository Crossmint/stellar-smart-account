use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, BytesN as _, Ledger as _};
use soroban_sdk::{map, vec, Address, BytesN, Env, IntoVal, Vec};

use crate::account::SmartAccount;
use crate::auth::proof::SignatureProofs;
use crate::error::Error;
use crate::tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait as _};
use smart_account_interfaces::{
    SignerPolicy, SignerRole, SmartAccountInterface as _, SpendTrackerKey, TokenTransferPolicy,
};

// ============================================================================
// Helpers
// ============================================================================

fn make_policy(env: &Env, token: &Address, limit: i128) -> TokenTransferPolicy {
    TokenTransferPolicy {
        policy_id: BytesN::random(env),
        token: token.clone(),
        limit,
        reset_window_secs: 0,
        allowed_recipients: Vec::new(env),
        expiration: 0,
    }
}

fn make_transfer_context(env: &Env, token: &Address, to: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: "transfer".into_val(env),
        args: (Address::generate(env), to, amount).into_val(env),
    })
}

fn setup_account_with_policy(
    env: &Env,
    policy: &TokenTransferPolicy,
) -> (Address, Ed25519TestSigner) {
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(env);
    let signer_policy = SignerPolicy::TokenTransferPolicy(policy.clone());
    let standard_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(Some(vec![env, signer_policy])));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![env, admin_signer, standard_signer.into_signer(env)],
            Vec::<Address>::new(env),
        ),
    );
    (contract_id, standard_signer)
}

fn check_auth(
    env: &Env,
    contract_id: &Address,
    signer: &Ed25519TestSigner,
    contexts: &Vec<Context>,
) -> Result<(), Error> {
    let payload = BytesN::random(env);
    let (signer_key, proof) = signer.sign(env, &payload);
    let auth_payloads = SignatureProofs(map![env, (signer_key, proof)]);
    env.try_invoke_contract_check_auth::<Error>(
        contract_id,
        &payload,
        auth_payloads.into_val(env),
        contexts,
    )
    .map_err(|e| match e {
        Ok(err) => err,
        Err(e) => panic!("Unexpected invoke error: {:?}", e),
    })
}

// ============================================================================
// Basic authorization tests
// ============================================================================

#[test]
fn test_transfer_within_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 500)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_transfer_exceeds_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 1001)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_transfer_at_exact_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 1000)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_zero_amount_transfer() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 0)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

// ============================================================================
// Cumulative spending tests
// ============================================================================

#[test]
fn test_cumulative_spending_second_transfer_exceeds() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // First transfer: 600 (within limit)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 600)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Second transfer: 500 (cumulative 1100 > 1000)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 500)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_cumulative_spending_multiple_within_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // Three transfers: 300 + 300 + 400 = 1000 (at the limit)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 300)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 300)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 400)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Next transfer should fail
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 1)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_batch_transfer_cumulative_in_single_auth() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // Two transfers in one auth batch: 600 + 500 = 1100 > 1000
    let contexts = vec![
        &env,
        make_transfer_context(&env, &token, &to, 600),
        make_transfer_context(&env, &token, &to, 500),
    ];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

// ============================================================================
// Reset window tests
// ============================================================================

#[test]
fn test_reset_window_resets_spending() {
    let env = setup();
    env.ledger().set_timestamp(1000);

    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 500);
    policy.reset_window_secs = 60; // 60 second window
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // Spend 400 (within 500 limit)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 400)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Spend 200 more (cumulative 600 > 500, should fail)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 200)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);

    // Advance time past the reset window
    env.ledger().set_timestamp(1061); // 61 seconds later

    // Now spending should have reset, 200 should work
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 200)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_reset_window_does_not_reset_before_elapsed() {
    let env = setup();
    env.ledger().set_timestamp(1000);

    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 500);
    policy.reset_window_secs = 60;
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // Spend 400
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 400)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Advance time but NOT past window (59 seconds)
    env.ledger().set_timestamp(1059);

    // Spend 200 more (cumulative 600 > 500, should still fail)
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 200)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

// ============================================================================
// Expiration tests
// ============================================================================

#[test]
fn test_expired_policy_denied() {
    let env = setup();
    env.ledger().set_timestamp(1000);

    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.expiration = 2000; // expires at timestamp 2000
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);

    // Before expiration: should work
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 100)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // After expiration: should fail
    env.ledger().set_timestamp(2001);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 100)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_no_expiration_always_valid() {
    let env = setup();
    env.ledger().set_timestamp(1_000_000_000);

    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000); // expiration = 0
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 100)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

// ============================================================================
// Token-exclusive enforcement tests
// ============================================================================

#[test]
fn test_wrong_token_denied() {
    let env = setup();
    let token = Address::generate(&env);
    let wrong_token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &wrong_token, &to, 100)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_wrong_function_denied() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    // Call "approve" on the correct token
    let contexts = vec![
        &env,
        Context::Contract(ContractContext {
            contract: token.clone(),
            fn_name: "approve".into_val(&env),
            args: (Address::generate(&env), Address::generate(&env), 100i128).into_val(&env),
        }),
    ];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_mixed_contexts_denied() {
    let env = setup();
    let token = Address::generate(&env);
    let other_contract = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let to = Address::generate(&env);
    // One valid transfer + one call to another contract
    let contexts = vec![
        &env,
        make_transfer_context(&env, &token, &to, 100),
        Context::Contract(ContractContext {
            contract: other_contract,
            fn_name: "do_something".into_val(&env),
            args: ().into_val(&env),
        }),
    ];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

// ============================================================================
// Recipient allowlist tests
// ============================================================================

#[test]
fn test_allowlist_allowed_recipient() {
    let env = setup();
    let token = Address::generate(&env);
    let allowed = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.allowed_recipients = vec![&env, allowed.clone()];
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 100)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_allowlist_disallowed_recipient() {
    let env = setup();
    let token = Address::generate(&env);
    let allowed = Address::generate(&env);
    let disallowed = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.allowed_recipients = vec![&env, allowed];
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let contexts = vec![&env, make_transfer_context(&env, &token, &disallowed, 100)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_empty_allowlist_allows_any_recipient() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000); // empty allowlist
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    let random_recipient = Address::generate(&env);
    let contexts = vec![
        &env,
        make_transfer_context(&env, &token, &random_recipient, 100),
    ];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_allowlist_multiple_recipients() {
    let env = setup();
    let token = Address::generate(&env);
    let allowed_1 = Address::generate(&env);
    let allowed_2 = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.allowed_recipients = vec![&env, allowed_1.clone(), allowed_2.clone()];
    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    // Transfer to first allowed
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed_1, 100)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Transfer to second allowed
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed_2, 100)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

// ============================================================================
// Policy lifecycle (on_add / on_revoke) tests
// ============================================================================

#[test]
fn test_on_add_initializes_tracker() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let tracker_key = SpendTrackerKey::TokenSpend(policy.policy_id.clone());

    // Register account with the policy (triggers on_add)
    let (contract_id, _) = setup_account_with_policy(&env, &policy);

    // Verify tracker was created in persistent storage
    env.as_contract(&contract_id, || {
        assert!(env.storage().persistent().has(&tracker_key));
    });
}

#[test]
fn test_on_revoke_cleans_up_tracker() {
    let env = setup();
    let token = Address::generate(&env);
    let policy = make_policy(&env, &token, 1000);
    let tracker_key = SpendTrackerKey::TokenSpend(policy.policy_id.clone());

    let signer_policy = SignerPolicy::TokenTransferPolicy(policy.clone());
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(Some(vec![&env, signer_policy])));
    let standard_signer_val = standard_signer.into_signer(&env);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, standard_signer_val.clone()],
            Vec::<Address>::new(&env),
        ),
    );

    // Verify tracker exists
    env.as_contract(&contract_id, || {
        assert!(env.storage().persistent().has(&tracker_key));
    });

    // Revoke the signer (triggers on_revoke which cleans up tracker)
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let signer_key = smart_account_interfaces::SignerKey::from(standard_signer_val.clone());
        SmartAccount::revoke_signer(&env, signer_key)
    })
    .unwrap();

    // Verify tracker is removed
    env.as_contract(&contract_id, || {
        assert!(!env.storage().persistent().has(&tracker_key));
    });
}

// ============================================================================
// on_add validation tests
// ============================================================================

#[test]
#[should_panic(expected = "#80")]
fn test_on_add_rejects_zero_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.limit = 0; // Invalid

    // This should panic during on_add (called from add_signer in __constructor)
    let _ = setup_account_with_policy(&env, &policy);
}

#[test]
#[should_panic(expected = "#80")]
fn test_on_add_rejects_negative_limit() {
    let env = setup();
    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.limit = -1; // Invalid

    let _ = setup_account_with_policy(&env, &policy);
}

#[test]
#[should_panic(expected = "#82")]
fn test_on_add_rejects_past_expiration() {
    let env = setup();
    env.ledger().set_timestamp(1000);
    let token = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 1000);
    policy.expiration = 999; // In the past

    let _ = setup_account_with_policy(&env, &policy);
}

// ============================================================================
// Integration: full __check_auth flow
// ============================================================================

#[test]
fn test_integration_full_check_auth_flow() {
    let env = setup();
    env.ledger().set_timestamp(1000);

    let token = Address::generate(&env);
    let allowed = Address::generate(&env);
    let mut policy = make_policy(&env, &token, 500);
    policy.reset_window_secs = 120;
    policy.allowed_recipients = vec![&env, allowed.clone()];
    policy.expiration = 5000;

    let (contract_id, signer) = setup_account_with_policy(&env, &policy);

    // Transfer 200 to allowed recipient -- should work
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 200)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Transfer 200 more -- cumulative 400, within limit
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 200)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Transfer 200 more -- cumulative 600 > 500, should fail
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 200)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);

    // Advance past reset window
    env.ledger().set_timestamp(1121); // 121 seconds later

    // Now should work again (limit reset)
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 200)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();

    // Advance past expiration
    env.ledger().set_timestamp(5001);

    // Should fail due to expiration
    let contexts = vec![&env, make_transfer_context(&env, &token, &allowed, 100)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

// ============================================================================
// Multi-policy tests (.any() semantics)
// ============================================================================

fn setup_account_with_policies(
    env: &Env,
    policies: Vec<SignerPolicy>,
) -> (Address, Ed25519TestSigner) {
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(env);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(Some(policies)));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![env, admin_signer, standard_signer.into_signer(env)],
            Vec::<Address>::new(env),
        ),
    );
    (contract_id, standard_signer)
}

#[test]
fn test_multi_policy_usdc_transfer_passes() {
    let env = setup();
    let usdc = Address::generate(&env);
    let eur = Address::generate(&env);

    let usdc_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &usdc, 1000));
    let eur_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &eur, 500));

    let policies = vec![&env, usdc_policy, eur_policy];
    let (contract_id, signer) = setup_account_with_policies(&env, policies);

    // USDC transfer within limit — should pass via USDC policy
    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &usdc, &to, 800)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_multi_policy_eur_transfer_passes() {
    let env = setup();
    let usdc = Address::generate(&env);
    let eur = Address::generate(&env);

    let usdc_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &usdc, 1000));
    let eur_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &eur, 500));

    let policies = vec![&env, usdc_policy, eur_policy];
    let (contract_id, signer) = setup_account_with_policies(&env, policies);

    // EUR transfer within limit — should pass via EUR policy
    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &eur, &to, 300)];
    check_auth(&env, &contract_id, &signer, &contexts).unwrap();
}

#[test]
fn test_multi_policy_exceeds_one_limit_other_passes() {
    let env = setup();
    let usdc = Address::generate(&env);
    let eur = Address::generate(&env);

    let usdc_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &usdc, 1000));
    let eur_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &eur, 500));

    let policies = vec![&env, usdc_policy, eur_policy];
    let (contract_id, signer) = setup_account_with_policies(&env, policies);

    // EUR transfer exceeding EUR limit — but USDC policy is irrelevant.
    // Neither policy authorizes 600 EUR (EUR limit is 500).
    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &eur, &to, 600)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_multi_policy_uncovered_token_denied() {
    let env = setup();
    let usdc = Address::generate(&env);
    let eur = Address::generate(&env);
    let gbp = Address::generate(&env); // Not covered by any policy

    let usdc_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &usdc, 1000));
    let eur_policy = SignerPolicy::TokenTransferPolicy(make_policy(&env, &eur, 500));

    let policies = vec![&env, usdc_policy, eur_policy];
    let (contract_id, signer) = setup_account_with_policies(&env, policies);

    // GBP transfer — no policy covers GBP, so neither authorizes
    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &gbp, &to, 100)];
    let err = check_auth(&env, &contract_id, &signer, &contexts).unwrap_err();
    assert_eq!(err, Error::InsufficientPermissions);
}

#[test]
fn test_standard_none_signer_can_do_non_admin_operations() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(None));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, standard_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Standard(None) signer should be able to authorize token transfers
    let token = Address::generate(&env);
    let to = Address::generate(&env);
    let contexts = vec![&env, make_transfer_context(&env, &token, &to, 100)];
    check_auth(&env, &contract_id, &standard_signer, &contexts).unwrap();
}

#[test]
#[should_panic(expected = "#80")]
fn test_standard_some_empty_vec_rejected() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    // Some(empty_vec) should be rejected during add_signer
    let standard_signer = Ed25519TestSigner::generate(SignerRole::Standard(Some(vec![&env])));
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, standard_signer.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
}
