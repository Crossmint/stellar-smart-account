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
// Dummy plugin contract that increments a counter on every on_auth.
// Returns () (void) — exercises ABI backwards compatibility.
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
// Plugin that rejects via new-style Err(PluginRejection::Rejected).
// -----------------------------------------------------------------------------

mod rejecting_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};

    use smart_account_interfaces::PluginRejection;

    #[contract]
    pub struct RejectingPlugin;

    #[contractimpl]
    impl RejectingPlugin {
        pub fn on_install(_env: &Env, _source: Address) {}

        pub fn on_uninstall(_env: &Env, _source: Address) {}

        pub fn on_auth(
            _env: &Env,
            _source: Address,
            _contexts: Vec<Context>,
        ) -> Result<(), PluginRejection> {
            Err(PluginRejection::Rejected)
        }
    }
}

use rejecting_plugin::RejectingPlugin;

// -----------------------------------------------------------------------------
// Plugin that bare-panics (technical failure, no contract error code).
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
            panic!("crashed");
        }
    }
}

use panicking_plugin::PanickingPlugin;

// -----------------------------------------------------------------------------
// Plugin that rejects with old-style panic_with_error! using a custom
// #[contracterror] (code 200, outside SmartAccountError/PluginRejection).
// Tests backwards compatibility with existing deployed plugins.
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
        pub fn on_install(_env: &Env, _source: Address) {}

        pub fn on_uninstall(_env: &Env, _source: Address) {}

        pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
            panic_with_error!(env, CustomPluginError::Rejected);
        }
    }
}

use custom_error_plugin::CustomErrorPlugin;

// -----------------------------------------------------------------------------
// Plugin that has on_install but no on_auth (missing callback).
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
    }
}

use no_auth_plugin::NoAuthPlugin;

// =============================================================================
// Helper: run __check_auth with given auth contexts
// =============================================================================

fn check_auth(
    env: &Env,
    smart_account_id: &Address,
    admin: &Ed25519TestSigner,
    contexts: &Vec<Context>,
) -> Result<(), Result<Error, soroban_sdk::InvokeError>> {
    let payload = BytesN::random(env);
    let (admin_key, admin_proof) = admin.sign(env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![env, (admin_key, admin_proof)]);
    env.try_invoke_contract_check_auth::<Error>(
        smart_account_id,
        &payload,
        auth_payloads.into_val(env),
        contexts,
    )
}

// =============================================================================
// Tests
// =============================================================================

// -----------------------------------------------------------------------------
// Test: Uninstall properly persists removal, plugin no longer receives on_auth
// -----------------------------------------------------------------------------

#[test]
fn test_uninstall_plugin_persists_removal() {
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

    let plugin_id = env.register(DummyPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    // Trigger on_auth
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

    assert!(env.as_contract(&smart_account_id, || {
        SmartAccount::is_plugin_installed(&env, plugin_id.clone())
    }));

    let count_after_install = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(count_after_install, 1);

    // Uninstall
    env.as_contract(&smart_account_id, || {
        SmartAccount::uninstall_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    assert!(!env.as_contract(&smart_account_id, || {
        SmartAccount::is_plugin_installed(&env, plugin_id.clone())
    }));

    // Trigger on_auth again — plugin should NOT run
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

    let count_after_uninstall = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(count_after_uninstall, 1);
}

// -----------------------------------------------------------------------------
// Test: New-style Err(PluginRejection::Rejected) blocks auth
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_new_style_rejection_blocks_auth() {
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

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

    assert_eq!(result, Err(Ok(Error::PluginOnAuthFailed)));
}

// -----------------------------------------------------------------------------
// Test: Old-style panic_with_error! with custom error still blocks (backwards compat)
// -----------------------------------------------------------------------------

#[test]
fn test_plugin_old_style_rejection_still_blocks() {
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

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

    assert_eq!(result, Err(Ok(Error::PluginOnAuthFailed)));
}

// -----------------------------------------------------------------------------
// Test: Old void-returning plugin still works (ABI backwards compat)
// -----------------------------------------------------------------------------

#[test]
fn test_old_void_plugin_still_works() {
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

    // DummyPlugin returns () — not Result<(), PluginRejection>
    let plugin_id = env.register(DummyPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

    // Void return and Ok(()) produce the same ABI representation.
    assert!(result.is_ok());

    let count = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(count, 1);
}

// -----------------------------------------------------------------------------
// Test: Bare panic!() is skipped as technical failure
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

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

    assert!(result.is_ok());
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

    let plugin_id = env.register(NoAuthPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

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

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);

    assert!(result.is_ok());

    let count = env.as_contract(&dummy_id, || DummyPlugin::get_count(&env));
    assert_eq!(count, 1, "DummyPlugin should still receive on_auth");
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

    for i in 0..10u32 {
        let plugin_id = env.register(DummyPlugin, ());
        env.as_contract(&smart_account_id, || {
            SmartAccount::install_plugin(&env, plugin_id.clone())
        })
        .unwrap_or_else(|e| panic!("Plugin {} install should succeed but got: {:?}", i, e));
    }

    let extra_plugin_id = env.register(DummyPlugin, ());
    let err = env
        .as_contract(&smart_account_id, || {
            SmartAccount::install_plugin(&env, extra_plugin_id.clone())
        })
        .unwrap_err();

    assert_eq!(err, Error::MaxPluginsReached);
}
