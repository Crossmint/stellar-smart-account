extern crate std;

use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, BytesN as _, Events, Ledger as _};
use soroban_sdk::{
    contract, contractimpl, contracttype, map, symbol_short, vec, Address, BytesN, Env, IntoVal,
    Symbol, TryFromVal, Vec,
};

use crate::account::SmartAccount;
use crate::auth::proof::SignatureProofs;
use crate::error::Error;
use crate::events::PolicyCallbackFailedEvent;
use crate::tests::test_utils::{
    get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _,
};
use smart_account_interfaces::{
    Ed25519Signer, ExternalPolicy, PolicyError, Signer, SignerKey, SignerPolicy, SignerRole,
    SmartAccountInterface, SmartAccountPolicy, TokenTransferPolicy,
};

// ============================================================================
// Configurable mock implementing SmartAccountPolicy
// ============================================================================

#[contracttype]
#[derive(Clone)]
struct MockConfig {
    is_auth_mode: u32,
    on_add_mode: u32,
    on_revoke_mode: u32,
}

const MODE_ALLOW: u32 = 0;
const MODE_REJECT: u32 = 1;
const MODE_PANIC: u32 = 2;
const MODE_REQUIRE_KEY: u32 = 3;

const CFG_KEY: Symbol = symbol_short!("cfg");
const IA_CALLS: Symbol = symbol_short!("ia_calls");
const OA_CALLS: Symbol = symbol_short!("oa_calls");
const OR_CALLS: Symbol = symbol_short!("or_calls");
const LAST_KEY: Symbol = symbol_short!("last_key");
const REQ_KEY: Symbol = symbol_short!("req_key");

#[contract]
pub struct MockPolicy;

#[contractimpl]
impl MockPolicy {
    pub fn configure(env: &Env, is_auth_mode: u32, on_add_mode: u32, on_revoke_mode: u32) {
        env.storage().instance().set(
            &CFG_KEY,
            &MockConfig {
                is_auth_mode,
                on_add_mode,
                on_revoke_mode,
            },
        );
    }

    pub fn set_required_key(env: &Env, key: SignerKey) {
        env.storage().instance().set(&REQ_KEY, &key);
    }

    pub fn ia_calls(env: &Env) -> u32 {
        env.storage().instance().get(&IA_CALLS).unwrap_or(0)
    }
    pub fn oa_calls(env: &Env) -> u32 {
        env.storage().instance().get(&OA_CALLS).unwrap_or(0)
    }
    pub fn or_calls(env: &Env) -> u32 {
        env.storage().instance().get(&OR_CALLS).unwrap_or(0)
    }
    pub fn last_key(env: &Env) -> Option<SignerKey> {
        env.storage().instance().get(&LAST_KEY)
    }

    fn cfg(env: &Env) -> MockConfig {
        env.storage()
            .instance()
            .get(&CFG_KEY)
            .unwrap_or(MockConfig {
                is_auth_mode: MODE_ALLOW,
                on_add_mode: MODE_ALLOW,
                on_revoke_mode: MODE_ALLOW,
            })
    }

    fn required_key(env: &Env) -> Option<SignerKey> {
        env.storage().instance().get(&REQ_KEY)
    }

    fn record_call(env: &Env, counter_key: &Symbol, signer_key: &SignerKey) {
        let n: u32 = env.storage().instance().get(counter_key).unwrap_or(0);
        env.storage().instance().set(counter_key, &(n + 1));
        env.storage().instance().set(&LAST_KEY, signer_key);
    }
}

#[contractimpl]
impl SmartAccountPolicy for MockPolicy {
    fn on_add(env: &Env, _source: Address, signer_key: SignerKey) -> Result<(), PolicyError> {
        Self::record_call(env, &OA_CALLS, &signer_key);
        match Self::cfg(env).on_add_mode {
            MODE_ALLOW => Ok(()),
            MODE_REJECT => Err(PolicyError::Other),
            MODE_PANIC => panic!("on_add panic"),
            _ => Ok(()),
        }
    }

    fn on_revoke(env: &Env, _source: Address, signer_key: SignerKey) -> Result<(), PolicyError> {
        Self::record_call(env, &OR_CALLS, &signer_key);
        match Self::cfg(env).on_revoke_mode {
            MODE_ALLOW => Ok(()),
            MODE_REJECT => Err(PolicyError::Other),
            MODE_PANIC => panic!("on_revoke panic"),
            _ => Ok(()),
        }
    }

    fn is_authorized(
        env: &Env,
        _source: Address,
        signer_key: SignerKey,
        _contexts: Vec<Context>,
    ) -> Result<(), PolicyError> {
        Self::record_call(env, &IA_CALLS, &signer_key);
        let cfg = Self::cfg(env);
        match cfg.is_auth_mode {
            MODE_ALLOW => Ok(()),
            MODE_REJECT => Err(PolicyError::Other),
            MODE_PANIC => panic!("is_authorized panic"),
            MODE_REQUIRE_KEY => match Self::required_key(env) {
                Some(k) if k == signer_key => Ok(()),
                _ => Err(PolicyError::Other),
            },
            _ => Ok(()),
        }
    }
}

// ============================================================================
// Test helpers
// ============================================================================

fn register_mock(env: &Env) -> Address {
    env.register(MockPolicy, ())
}

fn configure_mock(
    env: &Env,
    addr: &Address,
    is_auth_mode: u32,
    on_add_mode: u32,
    on_revoke_mode: u32,
) {
    let client = MockPolicyClient::new(env, addr);
    client.configure(&is_auth_mode, &on_add_mode, &on_revoke_mode);
}

fn set_required_key(env: &Env, addr: &Address, key: SignerKey) {
    let client = MockPolicyClient::new(env, addr);
    client.set_required_key(&key);
}

fn permission(addr: &Address) -> SignerPolicy {
    SignerPolicy::ExternalPolicy(ExternalPolicy {
        policy_address: addr.clone(),
    })
}

fn callback_failed_event_count(env: &Env, expected: &Address) -> u32 {
    env.events()
        .all()
        .iter()
        .filter(|(_addr, topics, data)| {
            let topic_match = topics.iter().any(|t| {
                Symbol::try_from_val(env, &t)
                    .map(|s| s == symbol_short!("cbfailed"))
                    .unwrap_or(false)
            });
            if !topic_match {
                return false;
            }
            PolicyCallbackFailedEvent::try_from_val(env, data)
                .map(|e| &e.policy_address == expected)
                .unwrap_or(false)
        })
        .count() as u32
}

// ============================================================================
// A. is_authorized return semantics
// ============================================================================

#[test]
fn happy_path_external_policy_authorizes() {
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (key, proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn intentional_rejection_emits_no_failure_event() {
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_REJECT, MODE_ALLOW, MODE_ALLOW);

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (key, proof)]);

    let res = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err();
    match res {
        Err(e) => panic!("unexpected host error: {:?}", e),
        Ok(e) => assert_eq!(e, Error::InsufficientPermissions),
    }
    // Intentional rejection ≠ fault: no failure event should be emitted.
    assert_eq!(callback_failed_event_count(&env, &mock_id), 0);
}

// ============================================================================
// B. Signer-key awareness
// ============================================================================

#[test]
fn signer_key_is_forwarded_to_permission_contract() {
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let standard_signer = standard.into_signer(&env);
    let standard_key: SignerKey = standard_signer.clone().into();
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard_signer],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (key, proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    let mock = MockPolicyClient::new(&env, &mock_id);
    assert_eq!(mock.last_key(), Some(standard_key));
}

#[test]
fn permission_can_distinguish_between_signers_sharing_a_contract() {
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let allowed = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let denied = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let allowed_signer = allowed.into_signer(&env);
    let allowed_key: SignerKey = allowed_signer.clone().into();
    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                allowed_signer,
                denied.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_REQUIRE_KEY, MODE_ALLOW, MODE_ALLOW);
    set_required_key(&env, &mock_id, allowed_key);

    // `allowed` signs → passes
    {
        let payload = BytesN::random(&env);
        let (k, p) = allowed.sign(&env, &payload);
        let auth = SignatureProofs(map![&env, (k, p)]);
        env.try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap();
    }

    // `denied` signs → fails with InsufficientPermissions
    {
        let payload = BytesN::random(&env);
        let (k, p) = denied.sign(&env, &payload);
        let auth = SignatureProofs(map![&env, (k, p)]);
        let res = env
            .try_invoke_contract_check_auth::<Error>(
                &contract_id,
                &payload,
                auth.into_val(&env),
                &vec![&env, get_token_auth_context(&env)],
            )
            .unwrap_err();
        match res {
            Err(e) => panic!("unexpected host error: {:?}", e),
            Ok(e) => assert_eq!(e, Error::InsufficientPermissions),
        }
    }
}

#[test]
fn multi_key_bundle_uses_correct_key_per_signer() {
    // Both signers in one bundle, mock allows only one of them.
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let signer_a = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let signer_b = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let signer_b_full = signer_b.into_signer(&env);
    let key_b: SignerKey = signer_b_full.clone().into();

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                signer_a.into_signer(&env),
                signer_b_full,
            ],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_REQUIRE_KEY, MODE_ALLOW, MODE_ALLOW);
    set_required_key(&env, &mock_id, key_b);

    let payload = BytesN::random(&env);
    let (ka, pa) = signer_a.sign(&env, &payload);
    let (kb, pb) = signer_b.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (ka, pa), (kb, pb)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// C. Fault containment
// ============================================================================

#[test]
fn panicking_is_authorized_is_contained_and_emits_event() {
    let env = setup();
    let mock_id = register_mock(&env);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );
    configure_mock(&env, &mock_id, MODE_PANIC, MODE_ALLOW, MODE_ALLOW);

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (key, proof)]);

    let res = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err();
    match res {
        Err(e) => panic!("unexpected host error: {:?}", e),
        Ok(e) => assert_eq!(e, Error::InsufficientPermissions),
    }
    assert!(callback_failed_event_count(&env, &mock_id) >= 1);
}

#[test]
fn rejecting_on_add_fails_signer_registration() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_REJECT, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(
            SmartAccount,
            (vec![&env, admin, standard], Vec::<Address>::new(&env)),
        );
    }));
    assert!(
        result.is_err(),
        "registration must fail when on_add rejects"
    );
}

#[test]
fn panicking_on_add_fails_signer_registration() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_PANIC, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(
            SmartAccount,
            (vec![&env, admin, standard], Vec::<Address>::new(&env)),
        );
    }));
    assert!(result.is_err(), "registration must fail when on_add panics");
}

#[test]
fn rejecting_on_revoke_does_not_block_revocation() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_REJECT);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);
    let standard_key: SignerKey = standard.clone().into();
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, admin, standard], Vec::<Address>::new(&env)),
    );

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_key.clone()).unwrap();
    });

    // Signer is gone from storage, even though the external rejected.
    // Non-blocking revoke: signer is gone from storage even though the
    // external rejected. Event emission is exercised by the auth-path test;
    // wallet-emitted events from `as_contract` blocks aren't observable in
    // this test runtime, so we don't assert on them here.
    assert!(env
        .as_contract(&contract_id, || {
            SmartAccount::has_signer(&env, standard_key).unwrap()
        })
        .eq(&false));
}

#[test]
fn panicking_on_revoke_does_not_block_revocation() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_PANIC);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);
    let standard_key: SignerKey = standard.clone().into();
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, admin, standard], Vec::<Address>::new(&env)),
    );

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_key.clone()).unwrap();
    });

    // Same rationale as rejecting_on_revoke: revoke is non-blocking even when
    // the external panics; event emission is verified in the auth-path test.
    assert!(env
        .as_contract(&contract_id, || {
            SmartAccount::has_signer(&env, standard_key).unwrap()
        })
        .eq(&false));
}

// ============================================================================
// D. OR semantics with sibling policies
// ============================================================================

fn dummy_token_transfer_policy(env: &Env) -> SignerPolicy {
    // Token policy that won't match the ContractContext used in tests.
    let token = Address::generate(env);
    SignerPolicy::TokenTransferPolicy(TokenTransferPolicy {
        policy_id: BytesN::from_array(env, &[7u8; 32]),
        token,
        limit: None,
        reset_window_secs: 0,
        allowed_recipients: None,
        expiration: 0,
    })
}

#[test]
fn external_policy_can_authorize_when_sibling_rejects() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![
            &env,
            dummy_token_transfer_policy(&env),
            permission(&mock_id),
        ]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (k, p) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (k, p)]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        // Token transfer context is for an unrelated address — token policy will reject.
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn two_external_policys_short_circuit_on_first_match() {
    let env = setup();
    let mock_yes = register_mock(&env);
    let mock_other = register_mock(&env);
    configure_mock(&env, &mock_yes, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);
    configure_mock(&env, &mock_other, MODE_REJECT, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_yes), permission(&mock_other)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (k, p) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (k, p)]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    // The first permission authorized, so the second one must NOT have been called.
    let other = MockPolicyClient::new(&env, &mock_other);
    assert_eq!(other.ia_calls(), 0);
}

#[test]
fn admin_signer_in_bundle_authorizes_when_external_policy_rejects() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_REJECT, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (ka, pa) = admin.sign(&env, &payload);
    let (ks, ps) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (ka, pa), (ks, ps)]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// E. Defense in depth
// ============================================================================

fn admin_op_context(env: &Env, contract_id: &Address) -> Context {
    // Self-targeted call simulating a wallet admin op (e.g. add_signer).
    let dummy = Ed25519TestSigner::generate(SignerRole::Standard(None, 0)).into_signer(env);
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "add_signer".into_val(env),
        args: (dummy,).into_val(env),
    })
}

#[test]
fn standard_signer_with_permission_cannot_perform_admin_ops() {
    let env = setup();
    let mock_id = register_mock(&env);
    // Permission is "open" — the role check must still block before it runs.
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Reset the call counter (on_add bumped it).
    let mock_client = MockPolicyClient::new(&env, &mock_id);
    let baseline_ia = mock_client.ia_calls();

    let payload = BytesN::random(&env);
    let (k, p) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (k, p)]);
    let res = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, admin_op_context(&env, &contract_id)],
        )
        .unwrap_err();
    match res {
        Err(e) => panic!("unexpected host error: {:?}", e),
        Ok(e) => assert_eq!(e, Error::InsufficientPermissions),
    }
    // The role check rejects before the permission contract is consulted.
    assert_eq!(mock_client.ia_calls(), baseline_ia);
}

#[test]
fn expired_signer_is_rejected_before_permission_is_invoked() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    env.ledger().with_mut(|l| l.timestamp = 1_000);
    let expiry = 2_000u64;

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        expiry,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let mock_client = MockPolicyClient::new(&env, &mock_id);
    let baseline_ia = mock_client.ia_calls();

    // Advance ledger past expiry.
    env.ledger().with_mut(|l| l.timestamp = expiry + 1);

    let payload = BytesN::random(&env);
    let (k, p) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (k, p)]);
    let res = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err();
    match res {
        Err(e) => panic!("unexpected host error: {:?}", e),
        Ok(e) => assert_eq!(e, Error::SignerExpired),
    }
    assert_eq!(mock_client.ia_calls(), baseline_ia);
}

// ============================================================================
// F. Lifecycle (on_add / on_revoke)
// ============================================================================

#[test]
fn on_add_is_invoked_with_correct_signer_key() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);
    let standard_key: SignerKey = standard.clone().into();

    env.register(
        SmartAccount,
        (vec![&env, admin, standard], Vec::<Address>::new(&env)),
    );

    let mock = MockPolicyClient::new(&env, &mock_id);
    assert_eq!(mock.oa_calls(), 1);
    assert_eq!(mock.last_key(), Some(standard_key));
}

#[test]
fn on_revoke_is_invoked_with_correct_signer_key() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);
    let standard_key: SignerKey = standard.clone().into();
    let contract_id = env.register(
        SmartAccount,
        (vec![&env, admin, standard], Vec::<Address>::new(&env)),
    );

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, standard_key.clone()).unwrap();
    });

    let mock = MockPolicyClient::new(&env, &mock_id);
    assert_eq!(mock.or_calls(), 1);
    assert_eq!(mock.last_key(), Some(standard_key));
}

// ============================================================================
// G. Update flows
// ============================================================================

#[test]
fn update_to_different_policy_address_fires_revoke_then_add() {
    let env = setup();
    let mock_a = register_mock(&env);
    let mock_b = register_mock(&env);
    configure_mock(&env, &mock_a, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);
    configure_mock(&env, &mock_b, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard_v1 = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_a)]),
        0,
    ))
    .into_signer(&env);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin, standard_v1.clone()],
            Vec::<Address>::new(&env),
        ),
    );

    let standard_v2 = if let Signer::Ed25519(core, _) = standard_v1.clone() {
        Signer::Ed25519(
            Ed25519Signer::new(core.public_key),
            SignerRole::Standard(Some(vec![&env, permission(&mock_b)]), 0),
        )
    } else {
        unreachable!()
    };

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, standard_v2).unwrap();
    });

    let a = MockPolicyClient::new(&env, &mock_a);
    let b = MockPolicyClient::new(&env, &mock_b);
    assert_eq!(a.oa_calls(), 1, "old permission was added once");
    assert_eq!(a.or_calls(), 1, "old permission was revoked on update");
    assert_eq!(b.oa_calls(), 1, "new permission was added on update");
    assert_eq!(b.or_calls(), 0);
}

#[test]
fn update_to_identical_permission_is_a_noop_for_external() {
    let env = setup();
    let mock_id = register_mock(&env);
    configure_mock(&env, &mock_id, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![&env, permission(&mock_id)]),
        0,
    ))
    .into_signer(&env);
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin, standard.clone()],
            Vec::<Address>::new(&env),
        ),
    );

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, standard).unwrap();
    });

    let mock = MockPolicyClient::new(&env, &mock_id);
    // Only the original on_add from registration; update should not re-add or revoke.
    assert_eq!(mock.oa_calls(), 1);
    assert_eq!(mock.or_calls(), 0);
}

// ============================================================================
// H. ABI mismatch — exercises the `Ok(Err(ConversionError))` arm of the
//    `try_is_authorized` dispatch in `external.rs`. This is the case where the
//    external contract responds successfully but with a value of the wrong
//    type (e.g. a v1-style `bool` return where the wallet expects
//    `Result<(), PolicyError>`). Critical for the V1→V2 migration safety
//    argument: a migrated v1-trait policy contract must fail-safe to "no auth".
// ============================================================================

/// Mock with the right `on_add` / `on_revoke` shapes (so signer registration
/// succeeds) but a wrong-typed `is_authorized` that returns `bool` instead
/// of `Result<(), PolicyError>`. Mirrors the v1 trait shape. Lives in its
/// own submodule so its `contractimpl`-generated XDR spec items don't
/// collide with `MockPolicy`'s.
mod wrong_abi {
    use super::*;

    #[contract]
    pub struct WrongAbiPolicy;

    #[contractimpl]
    impl WrongAbiPolicy {
        pub fn on_add(
            _env: &Env,
            _source: Address,
            _signer_key: SignerKey,
        ) -> Result<(), PolicyError> {
            Ok(())
        }

        pub fn on_revoke(
            _env: &Env,
            _source: Address,
            _signer_key: SignerKey,
        ) -> Result<(), PolicyError> {
            Ok(())
        }

        /// Returns `bool` instead of `Result<(), PolicyError>`. Even returning
        /// `true` here must NOT authorize the wallet — the SDK's `try_*`
        /// decode of `Tag::True` into the expected `()` fails with
        /// `ConversionError`.
        pub fn is_authorized(
            _env: &Env,
            _source: Address,
            _signer_key: SignerKey,
            _contexts: Vec<Context>,
        ) -> bool {
            true
        }
    }
}

#[test]
fn wrong_abi_is_authorized_is_treated_as_fault_and_logged() {
    let env = setup();
    let bad_id = env.register(wrong_abi::WrongAbiPolicy, ());

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(
        Some(vec![
            &env,
            SignerPolicy::ExternalPolicy(ExternalPolicy {
                policy_address: bad_id.clone(),
            }),
        ]),
        0,
    ));
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth = SignatureProofs(map![&env, (key, proof)]);

    let res = env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err();
    match res {
        Err(e) => panic!("unexpected host error: {:?}", e),
        Ok(e) => assert_eq!(e, Error::InsufficientPermissions),
    }
    // ABI mismatch is a fault, so the wallet must emit PolicyCallbackFailedEvent
    // (this is the `Ok(Err(_))` branch — distinct from intentional rejection,
    // which would be silent).
    assert!(callback_failed_event_count(&env, &bad_id) >= 1);
}
