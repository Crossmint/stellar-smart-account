#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, vec, Address, BytesN, Env, IntoVal, Symbol,
    Val, Vec,
};

use crate::test_constants::SMART_ACCOUNT_WASM;
use crate::{
    ContractCall, ContractDeploymentArgs, ContractFactory, ContractFactoryClient, FactoryError,
};

// ============================================================================
// PoC inner-call target used for auth propagation tests
// ============================================================================

#[contract]
pub struct PocCallee;

#[contractimpl]
impl PocCallee {
    pub fn ping(_env: Env) -> u32 {
        42
    }

    pub fn greet(_env: Env, caller: Address) -> Address {
        caller.require_auth();
        caller
    }

    pub fn boom(_env: Env) -> u32 {
        panic!("intentional failure")
    }

    pub fn greet_two(_env: Env, first: Address, second: Address) -> Address {
        first.require_auth();
        second.require_auth();
        first
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn create_factory_client<'a>(e: &Env) -> ContractFactoryClient<'a> {
    let address = e.register(ContractFactory, ());
    ContractFactoryClient::new(e, &address)
}

fn create_mock_salt(e: &Env, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = value;
    BytesN::from_array(e, &bytes)
}

fn default_deployment(e: &Env, salt_byte: u8) -> ContractDeploymentArgs {
    let wasm_bytes = soroban_sdk::Bytes::from_slice(e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    ContractDeploymentArgs {
        wasm_hash,
        salt: create_mock_salt(e, salt_byte),
        constructor_args: Vec::<Val>::new(e),
    }
}

// ============================================================================
// Existing tests
// ============================================================================

#[test]
fn test_get_deployed_address_without_deployment() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args = default_deployment(&e, 1);
    let predicted_address =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    assert_ne!(predicted_address, Address::generate(&e));
}

#[test]
fn test_different_salts_produce_different_addresses() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args1 = default_deployment(&e, 1);
    let args2 = default_deployment(&e, 2);

    let address1 =
        client.get_deployed_address(&args1.salt, &args1.wasm_hash, &args1.constructor_args);
    let address2 =
        client.get_deployed_address(&args2.salt, &args2.wasm_hash, &args2.constructor_args);

    assert_ne!(address1, address2);
}

#[test]
fn test_constructor_args_handling() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let wasm_hash = e.deployer().upload_contract_wasm(wasm_bytes);
    let arg1 = Address::generate(&e);
    let arg2 = 42u32;
    let constructor_args: Vec<Val> = vec![&e, arg1.into_val(&e), arg2.into_val(&e)];

    let deployed_address = client.get_deployed_address(&salt, &wasm_hash, &constructor_args);

    assert_ne!(deployed_address, Address::generate(&e));
}

#[test]
fn test_same_salt_produces_same_address() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args = default_deployment(&e, 1);

    let address1 = client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);
    let address2 = client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    assert_eq!(address1, address2);
}

#[test]
fn test_address_prediction_before_and_after_deployment() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args = default_deployment(&e, 42);

    let predicted_address =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    let deployed_address = client.deploy(&args);

    assert_eq!(predicted_address, deployed_address);

    let predicted_address_after =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);
    assert_eq!(predicted_address, predicted_address_after);
}

#[test]
fn test_deploy_idempotency() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args = default_deployment(&e, 1);

    let predicted_address =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    let deployed_address1 = client.deploy(&args);

    assert_eq!(deployed_address1, predicted_address);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let args = default_deployment(&e, 1);
        client.deploy(&args)
    }));

    assert!(
        result.is_err(),
        "Second deployment should fail - deploy function is not idempotent"
    );

    let predicted_address_after =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);
    assert_eq!(predicted_address, predicted_address_after);
    assert_eq!(deployed_address1, predicted_address_after);
}

#[test]
fn test_upload_and_deploy() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let salt = create_mock_salt(&e, 1);

    let wasm_bytes = soroban_sdk::Bytes::from_slice(&e, SMART_ACCOUNT_WASM);
    let constructor_args: Vec<Val> = vec![&e];

    let deployed_address = client.upload_and_deploy(&wasm_bytes, &salt, &constructor_args);

    assert!(!deployed_address.to_string().is_empty());
}

// ============================================================================
// deploy_idempotent_and_call
// ============================================================================

#[test]
fn test_deploy_idempotent_and_call_no_calls() {
    let e = Env::default();
    let client = create_factory_client(&e);

    let args = default_deployment(&e, 10);
    let predicted_address =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    let calls: Vec<ContractCall> = Vec::new(&e);
    let result = client.deploy_idempotent_and_call(&args, &calls);

    assert_eq!(result.address, predicted_address);
    assert_eq!(result.results.len(), 0);
}

#[test]
fn test_deploy_idempotent_and_call_multiple_calls_no_auth() {
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    let args = default_deployment(&e, 11);
    let predicted_address =
        client.get_deployed_address(&args.salt, &args.wasm_hash, &args.constructor_args);

    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "ping"),
            args: Vec::new(&e),
        },
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "ping"),
            args: Vec::new(&e),
        },
    ];

    let result = client.deploy_idempotent_and_call(&args, &calls);

    assert_eq!(result.address, predicted_address);
    assert_eq!(result.results.len(), 2);
    let r0: u32 = result.results.get(0).unwrap().into_val(&e);
    let r1: u32 = result.results.get(1).unwrap().into_val(&e);
    assert_eq!(r0, 42);
    assert_eq!(r1, 42);
}

#[test]
fn test_deploy_idempotent_and_call_inner_auth_succeeds_when_authorized() {
    // PoC that `require_auth` inside an inner call dispatched by the factory
    // is subject to Soroban's normal auth rules — it fails without any
    // authorization and succeeds once the caller's auth is made available.
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    let args = default_deployment(&e, 20);
    let authorizer = Address::generate(&e);

    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "greet"),
            args: vec![&e, authorizer.to_val()],
        },
    ];

    // `require_auth` fires from inside an inner call whose parent
    // (`deploy_idempotent_and_call`) did *not* itself require auth from
    // `authorizer`. That makes it a non-root authorization in the auth tree,
    // so the permissive helper is needed for mock_all_auths to accept it.
    e.mock_all_auths_allowing_non_root_auth();

    let result = client.deploy_idempotent_and_call(&args, &calls);

    assert_eq!(result.results.len(), 1);
    let returned: Address = result.results.get(0).unwrap().into_val(&e);
    assert_eq!(returned, authorizer);
}

#[test]
fn test_deploy_idempotent_and_call_inner_auth_fails_without_auth() {
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    let args = default_deployment(&e, 21);
    let authorizer = Address::generate(&e);

    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "greet"),
            args: vec![&e, authorizer.to_val()],
        },
    ];

    // Without any auth mocks the inner require_auth must fail, and the error
    // must surface as the typed FactoryError — not as a host-level abort.
    let err = client
        .try_deploy_idempotent_and_call(&args, &calls)
        .expect_err("inner call with unauthorized require_auth must fail")
        .expect("error must decode to FactoryError");
    assert_eq!(err, FactoryError::InnerCallFailed);
}

#[test]
fn test_deploy_idempotent_and_call_reverts_when_inner_panics() {
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    let args = default_deployment(&e, 30);
    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "boom"),
            args: Vec::new(&e),
        },
    ];

    let err = client
        .try_deploy_idempotent_and_call(&args, &calls)
        .expect_err("panicking inner call must surface as error")
        .expect("error must decode to FactoryError");
    assert_eq!(err, FactoryError::InnerCallFailed);
}

// ============================================================================
// PoC — end-to-end transaction requiring auth from an external account C
// ============================================================================
//
// These tests model a real transaction flow:
//
//   - An off-chain actor C (some Stellar account address) must authorize a
//     contract call that is *not* made directly from C but rather dispatched
//     as an inner call by the factory.
//
//   - The user (or orchestrator) submits a single top-level invocation
//     `factory.deploy_idempotent_and_call(args, [greet(C)])`. The
//     transaction envelope carries C's authorization entry.
//
//   - At host-call time, when `PocCallee::greet(C)` runs, `C.require_auth()`
//     must find a matching authorization provided by C. The host otherwise
//     aborts the whole transaction.
//
// Testing strategy:
//   We use `env.mock_all_auths_allowing_non_root_auth()`, which permits the
//   host to synthesize auth for `require_auth` calls made in sub-invocations
//   (C's auth is "non-root" because the factory call is the root and the
//   factory itself does not require C's auth). To *prove* that C's auth was
//   actually consumed — not silently skipped — each test asserts on
//   `env.auths()`, which lists every (address, invocation) pair whose auth
//   was required during the last contract call.

#[test]
fn poc_tx_requires_auth_from_external_account_c() {
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    // The external account C. In a production flow this would be an Ed25519
    // (or custom-account) address whose owner signs an auth entry off-chain.
    let c = Address::generate(&e);

    let args = default_deployment(&e, 100);
    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "greet"),
            args: vec![&e, c.to_val()],
        },
    ];

    // Allow non-root auth since C.require_auth() fires inside a sub-call of
    // the factory, and the factory itself does not require C's auth at its
    // top-level entrypoint.
    e.mock_all_auths_allowing_non_root_auth();

    let result = client.deploy_idempotent_and_call(&args, &calls);

    // Functional assertion: the call returned C as the greeted address.
    let returned: Address = result.results.get(0).unwrap().into_val(&e);
    assert_eq!(returned, c);

    // Auth assertion: env.auths() confirms C's authorization was required for
    // exactly the greet() invocation, which is the contract behavior we care
    // about in a real transaction.
    let auths = e.auths();
    assert!(
        auths.iter().any(|(addr, invocation)| {
            addr == &c
                && invocation.function
                    == soroban_sdk::testutils::AuthorizedFunction::Contract((
                        callee.clone(),
                        Symbol::new(&e, "greet"),
                        vec![&e, c.to_val()],
                    ))
        }),
        "expected C ({:?}) to authorize greet; got auths = {:?}",
        c,
        auths
    );
}

#[test]
fn poc_tx_without_c_auth_is_rejected() {
    // Same setup as the happy-path PoC, but with no auth mocks configured:
    // the host must abort the whole transaction because C.require_auth()
    // inside the inner call has nothing to match against. We assert that
    // failure surfaces as our typed FactoryError.
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());
    let c = Address::generate(&e);

    let args = default_deployment(&e, 101);
    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "greet"),
            args: vec![&e, c.to_val()],
        },
    ];

    let err = client
        .try_deploy_idempotent_and_call(&args, &calls)
        .expect_err("missing C auth must fail the transaction")
        .expect("error must decode to FactoryError");
    assert_eq!(err, FactoryError::InnerCallFailed);
}

#[test]
fn poc_tx_requires_auth_from_two_distinct_external_accounts() {
    // Two-account variant: both C1 and C2 must authorize the inner call.
    // Proves auth is tracked per-address, not globally: omitting either
    // account's entry from env.auths() would mean the corresponding
    // require_auth was not enforced.
    let e = Env::default();
    let client = create_factory_client(&e);
    let callee = e.register(PocCallee, ());

    let c1 = Address::generate(&e);
    let c2 = Address::generate(&e);

    let args = default_deployment(&e, 102);
    let calls: Vec<ContractCall> = vec![
        &e,
        ContractCall {
            target: callee.clone(),
            function: Symbol::new(&e, "greet_two"),
            args: vec![&e, c1.to_val(), c2.to_val()],
        },
    ];

    e.mock_all_auths_allowing_non_root_auth();
    let result = client.deploy_idempotent_and_call(&args, &calls);
    assert_eq!(result.results.len(), 1);

    let auths = e.auths();
    let expected_fn = soroban_sdk::testutils::AuthorizedFunction::Contract((
        callee.clone(),
        Symbol::new(&e, "greet_two"),
        vec![&e, c1.to_val(), c2.to_val()],
    ));
    assert!(
        auths
            .iter()
            .any(|(addr, inv)| addr == &c1 && inv.function == expected_fn),
        "C1 auth missing"
    );
    assert!(
        auths
            .iter()
            .any(|(addr, inv)| addr == &c2 && inv.function == expected_fn),
        "C2 auth missing"
    );
}
