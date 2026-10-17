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

// -----------------------------------------------------------------------------
// Real (non-mocked) authorization helpers
// -----------------------------------------------------------------------------

/// Invokes `fn_name(args)` on the smart account with a real authorization entry
/// signed by `signer`, so that the host runs the account's actual `__check_auth`
/// (including the plugin hooks) instead of mocked auth.
fn invoke_with_real_auth(
    env: &Env,
    smart_account_id: &Address,
    signer: &Ed25519TestSigner,
    fn_name: &str,
    args: Vec<soroban_sdk::Val>,
    nonce: i64,
) -> Result<(), soroban_sdk::InvokeError> {
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::{
        HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal,
        SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
    };
    use soroban_sdk::TryFromVal;

    let sc_args: std::vec::Vec<ScVal> = args
        .iter()
        .map(|v| ScVal::try_from_val(env, &v).unwrap())
        .collect();
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: smart_account_id.into(),
            function_name: fn_name.try_into().unwrap(),
            args: sc_args.try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    };

    let signature_expiration_ledger = env.ledger().sequence() + 100;
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: env.ledger().network_id().to_array().into(),
        nonce,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let digest: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
    let payload = BytesN::from_array(env, &digest);

    let (signer_key, proof) = signer.sign(env, &payload);
    let proofs = SignatureProofs(soroban_sdk::map![env, (signer_key, proof)]);
    let proofs_val: soroban_sdk::Val = proofs.into_val(env);
    let signature = ScVal::try_from_val(env, &proofs_val).unwrap();

    env.set_auths(&[SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: smart_account_id.into(),
            nonce,
            signature_expiration_ledger,
            signature,
        }),
        root_invocation,
    }]);

    env.try_invoke_contract::<(), Error>(smart_account_id, &Symbol::new(env, fn_name), args)
        .map(|_| ())
        .map_err(|e| match e {
            Ok(contract_err) => soroban_sdk::InvokeError::Contract(contract_err as u32),
            Err(invoke_err) => invoke_err,
        })
}

fn deploy_account_with_rejecting_plugin(env: &Env) -> (Ed25519TestSigner, Address, Address) {
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let plugin_id = env.register(RejectingPlugin, ());
    // Plugins passed to the constructor are installed without requiring auth.
    let smart_account_id = env.register(
        SmartAccount,
        (
            vec![env, admin.into_signer(env)],
            vec![env, plugin_id.clone()],
        ),
    );
    (admin, smart_account_id, plugin_id)
}

// -----------------------------------------------------------------------------
// Test: A plugin that always rejects on_auth cannot block its own uninstall
// -----------------------------------------------------------------------------

#[test]
fn test_rejecting_plugin_can_be_uninstalled_with_real_auth() {
    let env = setup();
    let (admin, smart_account_id, plugin_id) = deploy_account_with_rejecting_plugin(&env);

    // Sanity check: the plugin does veto ordinary admin operations.
    let new_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let res = invoke_with_real_auth(
        &env,
        &smart_account_id,
        &admin,
        "add_signer",
        vec![&env, new_signer.into_signer(&env).into_val(&env)],
        1,
    );
    assert!(res.is_err(), "rejecting plugin should block add_signer");

    // The admin can still uninstall the plugin through a real __check_auth.
    invoke_with_real_auth(
        &env,
        &smart_account_id,
        &admin,
        "uninstall_plugin",
        vec![&env, plugin_id.into_val(&env)],
        2,
    )
    .expect("admin must be able to uninstall a rejecting plugin");

    assert!(!env.as_contract(&smart_account_id, || {
        SmartAccount::is_plugin_installed(&env, plugin_id.clone())
    }));

    // With the plugin removed, ordinary admin operations work again.
    invoke_with_real_auth(
        &env,
        &smart_account_id,
        &admin,
        "add_signer",
        vec![&env, new_signer.into_signer(&env).into_val(&env)],
        3,
    )
    .expect("add_signer should succeed once the plugin is removed");
}

// -----------------------------------------------------------------------------
// Test: Plugins are not consulted for the account's recovery entry points only
// -----------------------------------------------------------------------------

#[test]
fn test_rejecting_plugin_is_skipped_only_for_recovery_contexts() {
    let env = setup();
    let (admin, smart_account_id, plugin_id) = deploy_account_with_rejecting_plugin(&env);

    let check = |contexts: Vec<Context>| {
        let payload = BytesN::random(&env);
        let (admin_key, admin_proof) = admin.sign(&env, &payload);
        let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (admin_key, admin_proof)]);
        env.try_invoke_contract_check_auth::<Error>(
            &smart_account_id,
            &payload,
            auth_payloads.into_val(&env),
            &contexts,
        )
    };
    let self_ctx = |fn_name: &str, args: Vec<soroban_sdk::Val>| {
        Context::Contract(soroban_sdk::auth::ContractContext {
            contract: smart_account_id.clone(),
            fn_name: Symbol::new(&env, fn_name),
            args,
        })
    };

    // Recovery entry points targeting the account itself bypass plugin hooks.
    let uninstall = self_ctx("uninstall_plugin", vec![&env, plugin_id.into_val(&env)]);
    let upgrade = self_ctx(
        "upgrade",
        vec![&env, BytesN::<32>::random(&env).into_val(&env)],
    );
    let migrate = self_ctx("migrate", vec![&env]);
    assert_eq!(check(vec![&env, uninstall.clone()]), Ok(()));
    assert_eq!(check(vec![&env, upgrade.clone()]), Ok(()));
    assert_eq!(check(vec![&env, migrate]), Ok(()));

    // Anything else is still subject to the plugin's veto, including bundling a
    // recovery call with another operation.
    assert_eq!(
        check(vec![&env, get_token_auth_context(&env)]),
        Err(Ok(Error::PluginOnAuthFailed))
    );
    assert_eq!(
        check(vec![&env, uninstall, get_token_auth_context(&env)]),
        Err(Ok(Error::PluginOnAuthFailed))
    );
    assert_eq!(
        check(vec![
            &env,
            self_ctx("install_plugin", vec![&env, plugin_id.into_val(&env)])
        ]),
        Err(Ok(Error::PluginOnAuthFailed))
    );
    // A same-named function on another contract is not exempt.
    let foreign_upgrade = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: plugin_id.clone(),
        fn_name: Symbol::new(&env, "upgrade"),
        args: vec![&env],
    });
    assert_eq!(
        check(vec![&env, foreign_upgrade]),
        Err(Ok(Error::PluginOnAuthFailed))
    );
}

// -----------------------------------------------------------------------------
// Test: The recovery exemption does not let standard signers bypass admin checks
// -----------------------------------------------------------------------------

#[test]
fn test_recovery_exemption_still_requires_admin() {
    let env = setup();
    let (_admin, smart_account_id, plugin_id) = deploy_account_with_rejecting_plugin(&env);

    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    env.mock_all_auths();
    env.as_contract(&smart_account_id, || {
        SmartAccount::add_signer(&env, standard.into_signer(&env))
    })
    .unwrap();

    let payload = BytesN::random(&env);
    let (key, proof) = standard.sign(&env, &payload);
    let auth_payloads = SignatureProofs(soroban_sdk::map![&env, (key, proof)]);
    let res = env.try_invoke_contract_check_auth::<Error>(
        &smart_account_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![
            &env,
            Context::Contract(soroban_sdk::auth::ContractContext {
                contract: smart_account_id.clone(),
                fn_name: Symbol::new(&env, "uninstall_plugin"),
                args: vec![&env, plugin_id.into_val(&env)],
            }),
        ],
    );
    assert_eq!(res, Err(Ok(Error::InsufficientPermissions)));
}
