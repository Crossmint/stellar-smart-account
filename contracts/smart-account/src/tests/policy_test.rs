use crate::auth::signers::Ed25519Signer;
use crate::interface::SmartAccountInterface;
use crate::tests::test_utils::TestSignerTrait as _;
use soroban_sdk::auth::Context;
use soroban_sdk::testutils::Events;
use soroban_sdk::{
    contract, contractimpl, symbol_short, vec, Address, Env, Symbol, TryFromVal, Vec,
};

use crate::account::SmartAccount;
use crate::auth::permissions::{SignerPolicy, SignerRole};
use crate::auth::policy::{ExternalPolicy, TimeBasedPolicy};
use crate::auth::signer::{Signer, SignerKey};
use crate::error::Error;
use crate::tests::test_utils::{setup, Ed25519TestSigner};

#[contract]
pub struct DummyExternalPolicy;

#[contractimpl]
impl DummyExternalPolicy {
    pub fn on_add(env: &Env, source: Address) -> Result<(), Error> {
        source.require_auth();
        env.events()
            .publish((symbol_short!("ON_ADD"),), env.current_contract_address());
        Ok(())
    }

    pub fn on_revoke(env: &Env, source: Address) -> Result<(), Error> {
        source.require_auth();
        env.events().publish(
            (symbol_short!("ON_REVOKE"),),
            env.current_contract_address(),
        );
        Ok(())
    }

    pub fn is_authorized(env: &Env, source: Address, _contexts: Vec<Context>) -> bool {
        env.events().publish(
            (symbol_short!("IS_AUTHZD"),),
            env.current_contract_address(),
        );
        source.require_auth();
        true
    }
}

fn ensure_policy_event_is_emmited(env: &Env, policy_id: Address, event_name: Symbol) {
    assert!(env.events().all().iter().any(|(_address, topics, data)| {
        topics.iter().any(|topic| {
            Symbol::try_from_val(env, &topic)
                .map(|s| s == event_name && Address::try_from_val(env, &data).unwrap() == policy_id)
                .unwrap_or(false)
        })
    }))
}

fn ensure_policy_event_is_not_emmited(env: &Env, policy_id: Address, event_name: Symbol) {
    assert!(!env.events().all().iter().any(|(_address, topics, data)| {
        topics.iter().any(|topic| {
            Symbol::try_from_val(env, &topic)
                .map(|s| s == event_name && Address::try_from_val(env, &data).unwrap() == policy_id)
                .unwrap_or(false)
        })
    }))
}

//
// Time-based policy
//
#[test]
fn test_deploy_with_time_based_policy() {
    let env = setup();
    let policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp(),
        not_after: env.ledger().timestamp() + 1000,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
#[should_panic]
fn test_deploy_with_time_based_policy_wrong_time_range() {
    let env = setup();
    let policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp() + 1000,
        not_after: env.ledger().timestamp() + 999,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
#[should_panic]
fn test_deploy_with_time_based_policy_wrong_not_after() {
    let env = setup();
    let policy = SignerPolicy::TimeWindowPolicy(TimeBasedPolicy {
        not_before: env.ledger().timestamp() + 1000,
        not_after: env.ledger().timestamp() + 999,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
fn test_signer_with_external_policy() {
    let env = setup();
    let policy_id = env.register(DummyExternalPolicy, ());
    let policy = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id.clone(),
    });

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer],
            Vec::<Address>::new(&env),
        ),
    );
}

#[test]
fn test_add_signer_with_external_polic_calls_on_add() {
    let env = setup();
    let policy_id = env.register(DummyExternalPolicy, ());
    let policy = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id.clone(),
    });

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer],
            Vec::<Address>::new(&env),
        ),
    );
    ensure_policy_event_is_emmited(&env, policy_id, symbol_short!("ON_ADD"));
}

#[test]
fn test_revoke_signer_with_external_polic_calls_on_revoke() {
    let env = setup();
    let policy_id = env.register(DummyExternalPolicy, ());
    let policy = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id.clone(),
    });

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy])).into_signer(&env);
    let account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer.clone()],
            Vec::<Address>::new(&env),
        ),
    );
    env.mock_all_auths();
    env.as_contract(&account_id, || {
        if let Signer::Ed25519(signer, _) = test_signer {
            let signer_key = SignerKey::Ed25519(signer.public_key);
            SmartAccount::revoke_signer(&env, signer_key)
        } else {
            unreachable!("Test signer is not an Ed25519 signer");
        }
    })
    .unwrap();

    ensure_policy_event_is_emmited(&env, policy_id, symbol_short!("ON_REVOKE"));
}

#[test]
fn test_update_signer_with_external_polic_lifecycle() {
    let env = setup();
    let policy_id_1 = env.register(DummyExternalPolicy, ());
    let policy_id_2 = env.register(DummyExternalPolicy, ());
    let policy_1 = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id_1.clone(),
    });
    let policy_2 = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id_2.clone(),
    });

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer_1 =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy_1])).into_signer(&env);
    if let Signer::Ed25519(core_signer, _) = test_signer_1.clone() {
        let test_signer_2 = Signer::Ed25519(
            Ed25519Signer::new(core_signer.public_key),
            SignerRole::Standard(vec![&env, policy_2]),
        );

        let account_id = env.register(
            SmartAccount,
            (
                vec![&env, admin_signer, test_signer_1.clone()],
                Vec::<Address>::new(&env),
            ),
        );
        env.mock_all_auths();

        ensure_policy_event_is_emmited(&env, policy_id_1.clone(), symbol_short!("ON_ADD"));

        env.as_contract(&account_id, || {
            SmartAccount::update_signer(&env, test_signer_2)
        })
        .unwrap();
        ensure_policy_event_is_emmited(&env, policy_id_1, symbol_short!("ON_REVOKE"));
        ensure_policy_event_is_emmited(&env, policy_id_2, symbol_short!("ON_ADD"));
    } else {
        unreachable!("Test signer is not an Ed25519 signer");
    }
}

#[test]
fn test_update_signer_with_external_polic_lifecycle_with_same_policy() {
    let env = setup();
    let policy_id_1 = env.register(DummyExternalPolicy, ());
    let policy_1 = SignerPolicy::ExternalValidatorPolicy(ExternalPolicy {
        policy_address: policy_id_1.clone(),
    });

    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer_1 =
        Ed25519TestSigner::generate(SignerRole::Standard(vec![&env, policy_1])).into_signer(&env);

    let account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin_signer, test_signer_1.clone()],
            Vec::<Address>::new(&env),
        ),
    );
    env.mock_all_auths();

    ensure_policy_event_is_emmited(&env, policy_id_1.clone(), symbol_short!("ON_ADD"));

    env.as_contract(&account_id, || {
        SmartAccount::update_signer(&env, test_signer_1)
    })
    .unwrap();
    ensure_policy_event_is_not_emmited(&env, policy_id_1.clone(), symbol_short!("ON_REVOKE"));
}
