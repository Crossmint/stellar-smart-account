#![cfg(test)]

extern crate std;

use soroban_sdk::{
    auth::Context, contract, contractimpl, symbol_short, testutils::BytesN as _, vec, Address,
    BytesN, Env, IntoVal, Symbol, Vec,
};

use crate::{
    account::SmartAccount,
    auth::{permissions::SignerRole, plugins::Plugin, proof::SignatureProofs},
    error::Error,
    interface::SmartAccountInterface,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
};

// -----------------------------------------------------------------------------
// Dummy plugin contract that increments a counter on every on_auth
// -----------------------------------------------------------------------------

const COUNT: Symbol = symbol_short!("cnt");

#[contract]
pub struct DummyPluginReverts;

#[contractimpl]
impl DummyPluginReverts {
    pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
        Ok(())
    }

    pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
        Ok(())
    }

    pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
        panic!("Im failing on purpose");
    }

    pub fn get_count(env: &Env) -> u32 {
        env.storage().instance().get(&COUNT).unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// Test: Uninstall properly persists removal, plugin no longer receives on_auth
// -----------------------------------------------------------------------------

#[test]
fn test_blocking_plugin_does_fail_on_auth() {
    let env = setup();
    env.mock_all_auths();

    // Deploy SmartAccount with one admin signer
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Plugin>::new(&env),
        ),
    );

    // Deploy dummy plugin
    let plugin_id = env.register(DummyPluginReverts, ());
    let plugin = Plugin::BlockingPlugin(plugin_id.clone());

    // Install plugin
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin.clone())
    })
    .unwrap();

    // Verify plugin is installed by triggering on_auth
    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![
        &env,
        (admin_key.clone(), admin_proof.clone())
    ]);

    env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap_err();
}

#[test]
fn test_non_blocking_plugin_does_not_fail_on_auth() {
    let env = setup();
    env.mock_all_auths();

    // Deploy SmartAccount with one admin signer
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Plugin>::new(&env),
        ),
    );

    // Deploy dummy plugin
    let plugin_id = env.register(DummyPluginReverts, ());
    let plugin = Plugin::NonBlockingPlugin(plugin_id.clone());

    // Install plugin
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin.clone())
    })
    .unwrap();

    // Verify plugin is installed by triggering on_auth
    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![
        &env,
        (admin_key.clone(), admin_proof.clone())
    ]);

    env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}
