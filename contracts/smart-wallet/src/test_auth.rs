#![cfg(test)]

extern crate std;

use soroban_sdk::auth::ContractContext;
use soroban_sdk::map;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::BytesN as _;
use soroban_sdk::testutils::Logs as _;
use soroban_sdk::vec;
use soroban_sdk::Address;
use soroban_sdk::BytesN;
use soroban_sdk::IntoVal;

use crate::test_utils::Ed25519TestSigner;
use crate::test_utils::TestSigner;

use super::*;

fn setup() -> Env {
    env_logger::init();
    Env::default()
}

fn get_token_auth_context(e: &Env) -> Context {
    let token_address = Address::generate(e);
    Context::Contract(ContractContext {
        contract: token_address,
        fn_name: "transfer".into_val(e),
        args: ((), (), 1000).into_val(e),
    })
}

#[test]
fn test_auth_ed25519_happy_case() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate();
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign(&env, &payload);
    let auth_payloads = AuthorizationPayloads(map![&env, (signer_key.clone(), proof.clone())]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

#[test]
fn test_auth_ed25519_wrong_signer() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate();
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let wrong_signer = Ed25519TestSigner::generate();
    let (signer_key, proof) = wrong_signer.sign(&env, &payload);
    let auth_payloads = AuthorizationPayloads(map![&env, (signer_key.clone(), proof.clone())]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap_err();
    let logs = env.logs().all();
    std::println!("{}", logs.join("\n"));
}
