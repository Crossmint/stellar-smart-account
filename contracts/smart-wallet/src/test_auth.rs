#![cfg(test)]

extern crate std;

use log::info;
use soroban_sdk::auth::ContractContext;
use soroban_sdk::map;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::BytesN as _;
use soroban_sdk::testutils::Logs as _;
use soroban_sdk::vec;
use soroban_sdk::Address;
use soroban_sdk::BytesN;
use soroban_sdk::IntoVal;

use crate::auth::signature::SignerProof;
use crate::test_utils::Ed25519TestSigner;
use crate::test_utils::TestSigner;

use super::*;

fn setup() -> Env {
    let _ = env_logger::try_init();
    Env::default()
}

fn print_logs(env: &Env) {
    let logs = env.logs().all();
    info!("{}", logs.join("\n"));
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
    print_logs(&env);
}

#[test]
fn test_auth_ed25519_no_configured_signer() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate();
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let wrong_signer = Ed25519TestSigner::generate();
    let (signer_key, proof) = wrong_signer.sign(&env, &payload);
    let auth_payloads = AuthorizationPayloads(map![&env, (signer_key.clone(), proof.clone())]);
    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::SignerNotFound),
    }
    print_logs(&env);
}

#[test]
#[should_panic]
fn test_auth_ed25519_wrong_signature() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate();
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let (signer_key, proof) = test_signer.sign(&env, &payload);
    let wrong_proof = if let SignerProof::Ed25519(_) = proof {
        SignerProof::Ed25519(BytesN::random(&env))
    } else {
        panic!("Invalid proof type");
    };
    let auth_payloads =
        AuthorizationPayloads(map![&env, (signer_key.clone(), wrong_proof.clone())]);
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
    print_logs(&env);
}

#[test]
fn test_auth_ed25519_no_signatures() {
    let env = setup();
    let test_signer = Ed25519TestSigner::generate();
    let contract_id = env.register(SmartWallet, (vec![&env, test_signer.into_signer(&env)],));
    let payload = BytesN::random(&env);
    let auth_payloads = AuthorizationPayloads(map![&env,]);
    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, get_token_auth_context(&env)],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::NoProofsInAuthEntry),
    }
    print_logs(&env);
}
