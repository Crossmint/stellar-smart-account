#![cfg(test)]

extern crate std;

use soroban_sdk::{
    auth::Context, contract, contractimpl, symbol_short, testutils::BytesN as _, vec, Address,
    BytesN, Env, IntoVal, Symbol, Vec,
};

use crate::{
    account::SmartAccount,
    auth::proof::SignatureProofs,
    error::Error,
    tests::test_utils::{get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _},
};
use smart_account_interfaces::{SignerRole, SmartAccountInterface};

// -----------------------------------------------------------------------------
// Dummy plugin contract that increments a counter on every on_auth
// -----------------------------------------------------------------------------

const COUNT: Symbol = symbol_short!("cnt");

#[contract]
pub struct DummyPlugin;

#[contractimpl]
impl DummyPlugin {
    pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
        Ok(())
    }

    pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
        Ok(())
    }

    pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
        let count: u32 = env.storage().instance().get(&COUNT).unwrap_or(0);
        env.storage().instance().set(&COUNT, &(count + 1));
    }

    pub fn get_count(env: &Env) -> u32 {
        env.storage().instance().get(&COUNT).unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// Plugin that intentionally rejects authorization (panic_with_error!)
// Wrapped in a submodule to avoid contractimpl symbol collisions.
// -----------------------------------------------------------------------------

mod rejecting_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, panic_with_error, Address, Env, Vec};

    use crate::error::Error;

    #[contract]
    pub struct RejectingPlugin;

    #[contractimpl]
    impl RejectingPlugin {
        pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
            // This uses panic_with_error! which produces Err(Ok(e)) in try_on_auth,
            // meaning the plugin intentionally rejected authorization.
            panic_with_error!(env, Error::PluginOnAuthFailed);
        }
    }
}

use rejecting_plugin::RejectingPlugin;

// -----------------------------------------------------------------------------
// Test: Uninstall properly persists removal, plugin no longer receives on_auth
// -----------------------------------------------------------------------------

#[test]
fn test_uninstall_plugin_persists_removal() {
    let env = setup();
    env.mock_all_auths();

    // Deploy SmartAccount with one admin signer
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Deploy dummy plugin
    let plugin_id = env.register(DummyPlugin, ());

    // Install plugin
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
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

    // Verify plugin is installed
    assert!(env.as_contract(&smart_account_id, || {
        SmartAccount::is_plugin_installed(&env, plugin_id.clone())
    }));

    // Verify plugin received on_auth call
    let count_after_install = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(
        count_after_install, 1,
        "Plugin should have received on_auth call"
    );

    // Uninstall plugin (FIX: removal now persisted to storage)
    env.as_contract(&smart_account_id, || {
        SmartAccount::uninstall_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    // Verify plugin is uninstalled
    assert!(!env.as_contract(&smart_account_id, || {
        SmartAccount::is_plugin_installed(&env, plugin_id.clone())
    }));

    // Trigger __check_auth again to see if plugin.on_auth still runs
    let payload2 = BytesN::random(&env);
    let (admin_key2, admin_proof2) = admin.sign(&env, &payload2);
    let auth_payloads2 = SignatureProofs(soroban_sdk::map![&env, (admin_key2, admin_proof2)]);

    env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload2,
        auth_payloads2.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    // Verify plugin did NOT receive second on_auth call (count should still be 1)
    let count_after_uninstall = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(
        count_after_uninstall, 1,
        "Plugin should NOT receive on_auth after uninstall"
    );
}

// -----------------------------------------------------------------------------
// Test: Intentional plugin rejection blocks authorization
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_intentional_rejection_blocks_auth() {
    let env = setup();
    env.mock_all_auths();

    // Deploy SmartAccount with one admin signer
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Deploy and install the rejecting plugin
    let plugin_id = env.register(RejectingPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    // Try to authenticate
    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // The rejecting plugin (panic_with_error!) should cause PluginOnAuthFailed,
    // blocking authorization. This exercises the Err(Ok(_)) branch in
    // call_plugins_on_auth.
    assert_eq!(result, Err(Ok(Error::PluginOnAuthFailed)));
}

// -----------------------------------------------------------------------------
// Test: Installing more than MAX_PLUGINS plugins fails with MaxPluginsReached
// -----------------------------------------------------------------------------

#[test]
fn test_max_plugins_limit() {
    let env = setup();
    env.mock_all_auths();

    // Deploy SmartAccount with one admin signer
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Install 10 plugins (the maximum allowed)
    for i in 0..10u32 {
        let plugin_id = env.register(DummyPlugin, ());
        env.as_contract(&smart_account_id, || {
            SmartAccount::install_plugin(&env, plugin_id.clone())
        })
        .unwrap_or_else(|e| panic!("Plugin {} install should succeed but got: {:?}", i, e));
    }

    // The 11th plugin should fail with MaxPluginsReached
    let extra_plugin_id = env.register(DummyPlugin, ());
    let err = env
        .as_contract(&smart_account_id, || {
            SmartAccount::install_plugin(&env, extra_plugin_id.clone())
        })
        .unwrap_err();

    assert_eq!(err, Error::MaxPluginsReached);
}
