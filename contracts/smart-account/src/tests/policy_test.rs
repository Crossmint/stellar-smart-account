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
        env.events().publish((symbol_short!("ON_ADD"),), &source);
        Ok(())
    }

    pub fn on_revoke(env: &Env, source: Address) -> Result<(), Error> {
        source.require_auth();
        env.events().publish((symbol_short!("ON_REVOKE"),), &source);
        Ok(())
    }

    pub fn is_authorized(env: &Env, source: Address, _contexts: Vec<Context>) -> bool {
        env.events().publish((symbol_short!("IS_AUTHZD"),), &source);
        source.require_auth();
        true
    }
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
    assert!(env.events().all().iter().any(|(address, topics, data)| {
        topics.iter().any(|topic| {
            Symbol::try_from_val(&env, &topic)
                .map(|s| s == symbol_short!("ON_ADD"))
                .unwrap_or(false)
        })
    }));
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

    assert!(env.events().all().iter().any(|(address, topics, data)| {
        topics.iter().any(|topic| {
            Symbol::try_from_val(&env, &topic)
                .map(|s| s == symbol_short!("ON_REVOKE"))
                .unwrap_or(false)
        })
    }));
}
