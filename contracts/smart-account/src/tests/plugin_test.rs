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
            // This uses panic_with_error! which produces a Contract-type error,
            // meaning the plugin intentionally rejected authorization.
            panic_with_error!(env, Error::PluginOnAuthFailed);
        }
    }
}

use rejecting_plugin::RejectingPlugin;

// -----------------------------------------------------------------------------
// Plugin that bare-panics (technical failure, no contract error code)
// -----------------------------------------------------------------------------

mod panicking_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};

    use crate::error::Error;

    #[contract]
    pub struct PanickingPlugin;

    #[contractimpl]
    impl PanickingPlugin {
        pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        pub fn on_auth(_env: &Env, _source: Address, _contexts: Vec<Context>) {
            // Bare panic! produces Error(Context, InvalidAction) — NOT a
            // contract error. The authorizer skips this as a technical failure.
            panic!("crashed");
        }
    }
}

use panicking_plugin::PanickingPlugin;

// -----------------------------------------------------------------------------
// Plugin that rejects with its own #[contracterror] (code outside SmartAccountError)
// -----------------------------------------------------------------------------

mod custom_error_plugin {
    use soroban_sdk::{
        auth::Context, contract, contracterror, contractimpl, panic_with_error, Address, Env, Vec,
    };

    #[contracterror]
    #[derive(Copy, Clone, Debug, PartialEq)]
    #[repr(u32)]
    pub enum CustomPluginError {
        Rejected = 200,
    }

    #[contract]
    pub struct CustomErrorPlugin;

    #[contractimpl]
    impl CustomErrorPlugin {
        pub fn on_install(_env: &Env, _source: Address) {
            // no-op
        }

        pub fn on_uninstall(_env: &Env, _source: Address) {
            // no-op
        }

        pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
            // Deliberate rejection using a custom error type whose code (200)
            // does not match any SmartAccountError variant. This produces
            // Error(Contract, #200) — still a contract-type error, so the
            // authorizer must treat it as an intentional rejection.
            panic_with_error!(env, CustomPluginError::Rejected);
        }
    }
}

use custom_error_plugin::CustomErrorPlugin;

// -----------------------------------------------------------------------------
// Plugin that has on_install but no on_auth (missing callback)
// -----------------------------------------------------------------------------

mod no_auth_plugin {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    use crate::error::Error;

    #[contract]
    pub struct NoAuthPlugin;

    #[contractimpl]
    impl NoAuthPlugin {
        pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }

        // Deliberately NO on_auth method — simulates a misconfigured or
        // upgraded contract that lost its on_auth callback.
    }
}

use no_auth_plugin::NoAuthPlugin;

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

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let plugin_id = env.register(RejectingPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // The rejecting plugin uses panic_with_error! with a SmartAccountError code,
    // producing Error(Contract, #103). The authorizer sees ScErrorType::Contract
    // and blocks authorization.
    assert_eq!(result, Err(Ok(Error::PluginOnAuthFailed)));
}

// -----------------------------------------------------------------------------
// Test: Installing more than MAX_PLUGINS plugins fails with MaxPluginsReached
// -----------------------------------------------------------------------------

#[test]
fn test_max_plugins_limit() {
    let env = setup();
    env.mock_all_auths();

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

// -----------------------------------------------------------------------------
// Test: Bare panic!() in plugin is skipped as technical failure
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_bare_panic_skipped() {
    let env = setup();
    env.mock_all_auths();

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let plugin_id = env.register(PanickingPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // A bare panic! produces Error(Context, InvalidAction) — NOT ScErrorType::Contract.
    // The authorizer treats this as a technical failure and skips the plugin.
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------------
// Test: Plugin with custom #[contracterror] blocks auth
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_custom_error_blocks_auth() {
    let env = setup();
    env.mock_all_auths();

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let plugin_id = env.register(CustomErrorPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // panic_with_error! with a custom #[contracterror] (code 200, not in
    // SmartAccountError) produces Error(Contract, #200). The error type is
    // still ScErrorType::Contract, so it's an intentional rejection.
    assert_eq!(result, Err(Ok(Error::PluginOnAuthFailed)));
}

// -----------------------------------------------------------------------------
// Test: Missing on_auth callback is skipped as technical failure
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_missing_on_auth_skipped() {
    let env = setup();
    env.mock_all_auths();

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Install a plugin that has on_install but NOT on_auth
    let plugin_id = env.register(NoAuthPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // Missing on_auth function produces Error(Context, InvalidAction) — NOT
    // ScErrorType::Contract. The authorizer treats this as a technical failure
    // and skips the plugin, preventing a misconfigured contract from locking
    // the wallet.
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------------
// Test: Crashing plugin does not prevent other plugins from running
// -----------------------------------------------------------------------------

#[test]
fn test_mixed_plugins_crash_does_not_block() {
    let env = setup();
    env.mock_all_auths();

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Install both plugins
    let dummy_id = env.register(DummyPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, dummy_id.clone())
    })
    .unwrap();

    let panicking_id = env.register(PanickingPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, panicking_id.clone())
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);

    let result = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    );

    // Auth succeeds — the panicking plugin is skipped as a technical failure.
    assert!(result.is_ok());

    // DummyPlugin still received its on_auth call.
    let count = env.as_contract(&dummy_id, || DummyPlugin::get_count(&env));
    assert_eq!(count, 1, "DummyPlugin should still receive on_auth");
}
