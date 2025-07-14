use crate::tests::test_utils::TestSignerTrait as _;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address};

use crate::account::SmartAccount;
use crate::auth::permissions::{SignerPolicy, SignerRole};
use crate::auth::policy::{ContractAllowListPolicy, ContractDenyListPolicy, TimeBasedPolicy};
use crate::tests::test_utils::{setup, Ed25519TestSigner};

//
// Allowlist policy
//
#[test]
fn test_deploy_with_allowlist_policy() {
    let env = setup();
    let policy = SignerPolicy::ContractAllowList(ContractAllowListPolicy {
        allowed_contracts: vec![&env, Address::generate(&env)],
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, policy])).into_signer(&env);
    env.register(SmartAccount, (vec![&env, admin_signer, test_signer],));
}

//
// Denylist policy
//
#[test]
fn test_deploy_with_denylist_policy() {
    let env = setup();
    let policy = SignerPolicy::ContractDenyList(ContractDenyListPolicy {
        denied_contracts: vec![&env, Address::generate(&env)],
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, policy])).into_signer(&env);
    env.register(SmartAccount, (vec![&env, admin_signer, test_signer],));
}

//
// Time-based policy
//
#[test]
fn test_deploy_with_time_based_policy() {
    let env = setup();
    let policy = SignerPolicy::TimeBased(TimeBasedPolicy {
        not_before: env.ledger().timestamp(),
        not_after: env.ledger().timestamp() + 1000,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, policy])).into_signer(&env);
    env.register(SmartAccount, (vec![&env, admin_signer, test_signer],));
}

#[test]
#[should_panic]
fn test_deploy_with_time_based_policy_wrong_time_range() {
    let env = setup();
    let policy = SignerPolicy::TimeBased(TimeBasedPolicy {
        not_before: env.ledger().timestamp() + 1000,
        not_after: env.ledger().timestamp() + 999,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, policy])).into_signer(&env);
    env.register(SmartAccount, (vec![&env, admin_signer, test_signer],));
}

#[test]
#[should_panic]
fn test_deploy_with_time_based_policy_wrong_not_after() {
    let env = setup();
    let policy = SignerPolicy::TimeBased(TimeBasedPolicy {
        not_before: env.ledger().timestamp() + 1000,
        not_after: env.ledger().timestamp() + 999,
    });
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin).into_signer(&env);
    let test_signer =
        Ed25519TestSigner::generate(SignerRole::Restricted(vec![&env, policy])).into_signer(&env);
    env.register(SmartAccount, (vec![&env, admin_signer, test_signer],));
}
