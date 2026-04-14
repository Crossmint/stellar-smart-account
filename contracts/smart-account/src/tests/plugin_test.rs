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

// =============================================================================
// ABI backwards compatibility — exhaustive tests
//
// These tests verify that every old-style plugin pattern continues to work
// after the on_auth return type changed from () to Result<(), PluginRejection>.
// =============================================================================

// -- Additional old-style plugin variants ------------------------------------

/// Old-style plugin that does storage writes, event emission, and returns void.
/// Simulates a "real" plugin doing actual work.
mod storage_event_plugin {
    use soroban_sdk::{
        auth::Context, contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
        Vec,
    };

    const KEY: Symbol = symbol_short!("se_cnt");

    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct PluginAuthEvent {
        pub source: Address,
        pub count: u32,
    }

    #[contract]
    pub struct StorageEventPlugin;

    #[contractimpl]
    impl StorageEventPlugin {
        pub fn on_install(_env: &Env, _source: Address) {}
        pub fn on_uninstall(_env: &Env, _source: Address) {}
        pub fn on_auth(env: &Env, source: Address, _contexts: Vec<Context>) {
            let count: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
            let new_count = count + 1;
            env.storage().instance().set(&KEY, &new_count);
            env.events().publish(
                (symbol_short!("AUTH"),),
                PluginAuthEvent {
                    source,
                    count: new_count,
                },
            );
        }
        pub fn get_count(env: &Env) -> u32 {
            env.storage().instance().get(&KEY).unwrap_or(0)
        }
    }
}

use storage_event_plugin::StorageEventPlugin;

/// Old-style plugin that returns Result<(), SmartAccountError> with Ok(()).
/// Some plugins may have adopted Result return early — this must still work.
mod result_ok_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};

    use crate::error::Error;

    #[contract]
    pub struct ResultOkPlugin;

    #[contractimpl]
    impl ResultOkPlugin {
        pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }
        pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }
        pub fn on_auth(_env: &Env, _source: Address, _contexts: Vec<Context>) -> Result<(), Error> {
            Ok(())
        }
    }
}

use result_ok_plugin::ResultOkPlugin;

/// Old-style plugin that returns Result<(), SmartAccountError> with Err.
/// Tests that a plugin rejecting via Result::Err with a SmartAccountError
/// is correctly classified as an intentional rejection.
mod result_err_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};

    use crate::error::Error;

    #[contract]
    pub struct ResultErrPlugin;

    #[contractimpl]
    impl ResultErrPlugin {
        pub fn on_install(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }
        pub fn on_uninstall(_env: &Env, _source: Address) -> Result<(), Error> {
            Ok(())
        }
        pub fn on_auth(_env: &Env, _source: Address, _contexts: Vec<Context>) -> Result<(), Error> {
            Err(Error::PluginOnAuthFailed)
        }
    }
}

use result_err_plugin::ResultErrPlugin;

/// Old-style plugin that uses panic_with_error! with a SmartAccountError code
/// (the pattern used by the original RejectingPlugin in pre-#115 code).
mod old_panic_with_known_error_plugin {
    use soroban_sdk::{auth::Context, contract, contractimpl, panic_with_error, Address, Env, Vec};

    use crate::error::Error;

    #[contract]
    pub struct OldPanicKnownErrorPlugin;

    #[contractimpl]
    impl OldPanicKnownErrorPlugin {
        pub fn on_install(_env: &Env, _source: Address) {}
        pub fn on_uninstall(_env: &Env, _source: Address) {}
        pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
            panic_with_error!(env, Error::PluginOnAuthFailed);
        }
    }
}

use old_panic_with_known_error_plugin::OldPanicKnownErrorPlugin;

// -- Direct try_on_auth result verification ----------------------------------

/// Calls try_on_auth directly on each plugin type and asserts the exact
/// Result variant. This is the most granular verification that the ABI
/// change doesn't alter the observable error classification.
#[test]
fn test_try_on_auth_result_variants() {
    use smart_account_interfaces::SmartAccountPluginClient;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::InvokeError;

    let env = setup();
    env.mock_all_auths();

    let source = soroban_sdk::Address::generate(&env);
    let contexts = Vec::new(&env);

    // 1. DummyPlugin (void return, succeeds) → Ok(Ok(()))
    let id = env.register(DummyPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Ok(Ok(()))),
        "void-returning success should be Ok(Ok(())): {:?}",
        res
    );

    // 2. StorageEventPlugin (void return, does real work) → Ok(Ok(()))
    let id = env.register(StorageEventPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Ok(Ok(()))),
        "void-returning plugin with storage+events should be Ok(Ok(())): {:?}",
        res
    );
    // Verify the plugin actually executed (side-effect check)
    let count = env.as_contract(&id, || StorageEventPlugin::get_count(&env));
    assert_eq!(count, 1, "StorageEventPlugin should have executed its body");

    // 3. ResultOkPlugin (returns Result<(), Error> with Ok(())) → Ok(Ok(()))
    let id = env.register(ResultOkPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Ok(Ok(()))),
        "Result::Ok(()) should be Ok(Ok(())): {:?}",
        res
    );

    // 4. RejectingPlugin (new-style Err(PluginRejection)) → Err(Ok(_))
    let id = env.register(RejectingPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Ok(_))),
        "new-style Err(PluginRejection) should be Err(Ok(_)): {:?}",
        res
    );

    // 5. ResultErrPlugin (Result::Err(SmartAccountError)) → Err(Err(Contract(_)))
    //    SmartAccountError code doesn't match PluginRejection, so TryFrom fails
    //    and it becomes InvokeError::Contract(code).
    let id = env.register(ResultErrPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Err(InvokeError::Contract(_)))),
        "Result::Err(SmartAccountError) should be Err(Err(Contract(_))): {:?}",
        res
    );

    // 6. OldPanicKnownErrorPlugin (panic_with_error! with SmartAccountError)
    //    → Err(Err(Contract(_))) because the SmartAccountError code doesn't match
    //    PluginRejection variants.
    let id = env.register(OldPanicKnownErrorPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Err(InvokeError::Contract(_)))),
        "panic_with_error!(SmartAccountError) should be Err(Err(Contract(_))): {:?}",
        res
    );

    // 7. CustomErrorPlugin (panic_with_error! with custom code 200)
    //    → Err(Err(Contract(200)))
    let id = env.register(CustomErrorPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Err(InvokeError::Contract(200)))),
        "panic_with_error!(CustomPluginError::Rejected=200) should be Err(Err(Contract(200))): {:?}",
        res
    );

    // 8. PanickingPlugin (bare panic!) → Err(Err(Abort))
    let id = env.register(PanickingPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Err(InvokeError::Abort))),
        "bare panic! should be Err(Err(Abort)): {:?}",
        res
    );

    // 9. NoAuthPlugin (missing on_auth) → Err(Err(Abort))
    let id = env.register(NoAuthPlugin, ());
    let res = SmartAccountPluginClient::new(&env, &id).try_on_auth(&source, &contexts);
    assert!(
        matches!(res, Err(Err(InvokeError::Abort))),
        "missing on_auth should be Err(Err(Abort)): {:?}",
        res
    );
}

// -- End-to-end auth tests for each old-style plugin -------------------------

#[test]
fn test_old_void_plugin_with_storage_and_events_works() {
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

    let plugin_id = env.register(StorageEventPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert!(
        result.is_ok(),
        "void plugin with storage+events should pass auth"
    );

    // Verify the plugin's side effects actually ran
    let count = env.as_contract(&plugin_id, || StorageEventPlugin::get_count(&env));
    assert_eq!(count, 1, "plugin should have incremented counter");

    // Run auth again to verify counter increments
    let result2 = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert!(result2.is_ok());
    let count2 = env.as_contract(&plugin_id, || StorageEventPlugin::get_count(&env));
    assert_eq!(count2, 2, "plugin should have incremented counter again");
}

#[test]
fn test_old_result_ok_plugin_works() {
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

    let plugin_id = env.register(ResultOkPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert!(
        result.is_ok(),
        "plugin returning Result::Ok(()) should pass auth"
    );
}

#[test]
fn test_old_result_err_plugin_blocks_auth() {
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

    let plugin_id = env.register(ResultErrPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert_eq!(
        result,
        Err(Ok(Error::PluginOnAuthFailed)),
        "plugin returning Result::Err should block auth"
    );
}

#[test]
fn test_old_panic_with_known_error_blocks_auth() {
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

    // This is the exact pattern used by the old RejectingPlugin before PR #115:
    // panic_with_error!(env, Error::PluginOnAuthFailed)
    let plugin_id = env.register(OldPanicKnownErrorPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, plugin_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert_eq!(
        result,
        Err(Ok(Error::PluginOnAuthFailed)),
        "old-style panic_with_error!(SmartAccountError) should still block auth"
    );
}

/// Mixed scenario: one old-style void plugin + one new-style Result plugin,
/// both approving. Verifies both can coexist.
#[test]
fn test_mixed_old_and_new_plugins_both_approve() {
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

    // Old-style void plugin
    let dummy_id = env.register(DummyPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, dummy_id.clone())
    })
    .unwrap();

    // Old-style Result::Ok plugin
    let result_ok_id = env.register(ResultOkPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, result_ok_id.clone())
    })
    .unwrap();

    // Old-style void plugin with side effects
    let storage_id = env.register(StorageEventPlugin, ());
    env.as_contract(&smart_account_id, || {
        SmartAccount::install_plugin(&env, storage_id.clone())
    })
    .unwrap();

    let contexts = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &smart_account_id, &admin, &contexts);
    assert!(result.is_ok(), "all three approving plugins should pass");

    // Verify both side-effect plugins ran
    let dummy_count = env.as_contract(&dummy_id, || DummyPlugin::get_count(&env));
    assert_eq!(dummy_count, 1);
    let storage_count = env.as_contract(&storage_id, || StorageEventPlugin::get_count(&env));
    assert_eq!(storage_count, 1);
}
