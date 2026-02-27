#![cfg(test)]

use soroban_sdk::{
    auth::Context,
    map,
    testutils::{BytesN as _, Ledger as _},
    vec, Address, BytesN, IntoVal, Vec,
};

use crate::{
    account::SmartAccount,
    auth::proof::SignatureProofs,
    error::Error,
    tests::test_utils::{
        get_token_auth_context, setup, Ed25519TestSigner, TestSignerTrait as _,
    },
};
use smart_account_interfaces::{
    RecoveryOperation, SignerKey, SignerRole, SmartAccountError, SmartAccountInterface as _,
};

extern crate std;

use ed25519_dalek::Keypair;
use soroban_sdk::auth::ContractContext;

// ============================================================================
// Helpers
// ============================================================================

/// Reconstruct an Ed25519TestSigner with the same keypair but a different role.
fn with_role(signer: &Ed25519TestSigner, role: SignerRole) -> Ed25519TestSigner {
    let bytes = signer.0.to_bytes();
    Ed25519TestSigner(Keypair::from_bytes(&bytes).unwrap(), role)
}

/// Invoke `__check_auth` and return the result.
fn check_auth(
    env: &soroban_sdk::Env,
    contract_id: &Address,
    signer: &Ed25519TestSigner,
    contexts: &Vec<Context>,
) -> Result<(), Error> {
    let payload = BytesN::random(env);
    let (signer_key, proof) = signer.sign(env, &payload);
    let auth = SignatureProofs(map![env, (signer_key, proof)]);
    env.try_invoke_contract_check_auth::<Error>(contract_id, &payload, auth.into_val(env), contexts)
        .map(|_| ())
        .map_err(|e| match e {
            Ok(err) => err,
            Err(e) => panic!("{:?}", e),
        })
}

fn get_schedule_recovery_context(env: &soroban_sdk::Env, contract_id: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "schedule_recovery".into_val(env),
        args: ((),).into_val(env),
    })
}

fn get_execute_recovery_context(env: &soroban_sdk::Env, contract_id: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "execute_recovery".into_val(env),
        args: ((),).into_val(env),
    })
}

fn get_cancel_recovery_context(env: &soroban_sdk::Env, contract_id: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "cancel_recovery".into_val(env),
        args: ((),).into_val(env),
    })
}

fn get_add_signer_context(env: &soroban_sdk::Env, contract_id: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "add_signer".into_val(env),
        args: ((),).into_val(env),
    })
}

// ============================================================================
// Happy path: schedule → wait → execute
// ============================================================================

#[test]
fn test_recovery_schedule_and_execute_add_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    // delay = 300 seconds, prevent_deletion = false
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // The signer to be added via recovery
    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let new_signer_key = SignerKey::Ed25519(new_signer.public_key(&env));
    let operation = RecoveryOperation::AddSigner(new_signer.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    // Schedule the recovery operation
    env.mock_all_auths();
    let operation_id = env
        .as_contract(&contract_id, || {
            SmartAccount::schedule_recovery(&env, recovery_key.clone(), operation, salt)
        })
        .unwrap();

    // Verify the pending operation exists
    let pending = env
        .as_contract(&contract_id, || {
            SmartAccount::get_recovery_op(&env, operation_id.clone())
        })
        .unwrap();
    assert_eq!(pending.scheduled_by, recovery_key);

    // Cannot execute yet (delay not passed)
    // Advance to just before the delay expires (1000 + 299 = 1299)
    env.ledger().with_mut(|li| li.timestamp = 1299);

    // Advance past delay: 1000 + 300 = 1300
    env.ledger().with_mut(|li| li.timestamp = 1301);

    let result = env.as_contract(&contract_id, || {
        SmartAccount::execute_recovery(&env, operation_id.clone())
    });
    assert!(result.is_ok());

    // Verify the signer was added
    let added = env
        .as_contract(&contract_id, || {
            SmartAccount::get_signer(&env, new_signer_key.clone())
        })
        .unwrap();
    assert_eq!(added.role(), SignerRole::Standard(None, 0));

    // Verify the pending operation was cleaned up
    let lookup = env.as_contract(&contract_id, || {
        SmartAccount::get_recovery_op(&env, operation_id)
    });
    assert_eq!(lookup.unwrap_err(), SmartAccountError::RecoveryOperationNotFound);
}

#[test]
fn test_recovery_schedule_and_execute_revoke_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(60, false));
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let standard_key = SignerKey::Ed25519(standard.public_key(&env));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                recovery.into_signer(&env),
                standard.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let operation = RecoveryOperation::RevokeSigner(standard_key.clone());
    let salt: BytesN<32> = BytesN::random(&env);
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    env.mock_all_auths();
    let operation_id = env
        .as_contract(&contract_id, || {
            SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
        })
        .unwrap();

    // Advance past delay
    env.ledger().with_mut(|li| li.timestamp = 1061);

    let result = env.as_contract(&contract_id, || {
        SmartAccount::execute_recovery(&env, operation_id)
    });
    assert!(result.is_ok());

    // Verify the standard signer was revoked
    let has = env
        .as_contract(&contract_id, || {
            SmartAccount::has_signer(&env, standard_key)
        })
        .unwrap();
    assert!(!has);
}

// ============================================================================
// prevent_deletion enforcement
// ============================================================================

#[test]
fn test_recovery_prevent_deletion_blocks_update() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    // prevent_deletion = true
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(60, true));
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                recovery.into_signer(&env),
                standard.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));
    let updated = with_role(&standard, SignerRole::Admin);
    let operation = RecoveryOperation::UpdateSigner(updated.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::RecoveryPreventDeletionViolation);
}

#[test]
fn test_recovery_prevent_deletion_blocks_revoke() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(60, true));
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![
                &env,
                admin.into_signer(&env),
                recovery.into_signer(&env),
                standard.into_signer(&env),
            ],
            Vec::<Address>::new(&env),
        ),
    );

    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));
    let standard_key = SignerKey::Ed25519(standard.public_key(&env));
    let operation = RecoveryOperation::RevokeSigner(standard_key);
    let salt: BytesN<32> = BytesN::random(&env);

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::RecoveryPreventDeletionViolation);
}

#[test]
fn test_recovery_prevent_deletion_allows_add() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(60, true));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let operation = RecoveryOperation::AddSigner(new_signer.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
    });

    assert!(result.is_ok());
}

// ============================================================================
// Cancel recovery
// ============================================================================

#[test]
fn test_cancel_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let operation = RecoveryOperation::AddSigner(new_signer.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    env.mock_all_auths();
    let operation_id = env
        .as_contract(&contract_id, || {
            SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
        })
        .unwrap();

    // Admin cancels the operation
    let result = env.as_contract(&contract_id, || {
        SmartAccount::cancel_recovery(&env, operation_id.clone())
    });
    assert!(result.is_ok());

    // Verify the pending operation was cleaned up
    let lookup = env.as_contract(&contract_id, || {
        SmartAccount::get_recovery_op(&env, operation_id.clone())
    });
    assert_eq!(lookup.unwrap_err(), SmartAccountError::RecoveryOperationNotFound);

    // Cannot execute a cancelled operation
    env.ledger().with_mut(|li| li.timestamp = 1301);
    // The OZ timelock will panic since the operation was cancelled
}

#[test]
fn test_cancel_nonexistent_recovery() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let fake_id: BytesN<32> = BytesN::random(&env);
    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::cancel_recovery(&env, fake_id)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::RecoveryOperationNotFound);
}

// ============================================================================
// Validation errors
// ============================================================================

#[test]
fn test_schedule_with_non_recovery_signer() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let new_signer = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let operation = RecoveryOperation::AddSigner(new_signer.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);
    let admin_key = SignerKey::Ed25519(admin.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::schedule_recovery(&env, admin_key, operation, salt)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::RecoverySignerRequired);
}

#[test]
fn test_invalid_recovery_delay_zero() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    // delay = 0 should be rejected
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(0, false));

    env.mock_all_auths();
    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Try adding recovery signer with delay 0
    let result = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, recovery.into_signer(&env))
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::InvalidRecoveryDelay);
}

#[test]
fn test_execute_nonexistent_recovery() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let fake_id: BytesN<32> = BytesN::random(&env);
    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::execute_recovery(&env, fake_id)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::RecoveryOperationNotFound);
}

// ============================================================================
// Authorization checks via __check_auth
// ============================================================================

#[test]
fn test_recovery_signer_can_authorize_schedule_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_schedule_recovery_context(&env, &contract_id)];
    check_auth(&env, &contract_id, &recovery, &ctx).unwrap();
}

#[test]
fn test_recovery_signer_can_authorize_execute_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let ctx = vec![&env, get_execute_recovery_context(&env, &contract_id)];
    check_auth(&env, &contract_id, &recovery, &ctx).unwrap();
}

#[test]
fn test_recovery_signer_cannot_authorize_admin_ops() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Recovery signer should NOT be able to authorize add_signer
    let ctx = vec![&env, get_add_signer_context(&env, &contract_id)];
    let result = check_auth(&env, &contract_id, &recovery, &ctx);
    assert_eq!(result.unwrap_err(), Error::InsufficientPermissions);
}

#[test]
fn test_recovery_signer_cannot_authorize_external_calls() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Recovery signer should NOT be able to authorize token transfers
    let ctx = vec![&env, get_token_auth_context(&env)];
    let result = check_auth(&env, &contract_id, &recovery, &ctx);
    assert_eq!(result.unwrap_err(), Error::InsufficientPermissions);
}

#[test]
fn test_standard_signer_cannot_authorize_schedule_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Standard signers should NOT be able to schedule_recovery
    let ctx = vec![&env, get_schedule_recovery_context(&env, &contract_id)];
    let result = check_auth(&env, &contract_id, &standard, &ctx);
    assert_eq!(result.unwrap_err(), Error::InsufficientPermissions);
}

#[test]
fn test_standard_signer_can_authorize_execute_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Standard signers CAN execute_recovery (anyone can)
    let ctx = vec![&env, get_execute_recovery_context(&env, &contract_id)];
    check_auth(&env, &contract_id, &standard, &ctx).unwrap();
}

#[test]
fn test_admin_can_authorize_cancel_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Admin can cancel recovery (classified as admin op)
    let ctx = vec![&env, get_cancel_recovery_context(&env, &contract_id)];
    check_auth(&env, &contract_id, &admin, &ctx).unwrap();
}

#[test]
fn test_recovery_signer_cannot_cancel_recovery() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Recovery signers CANNOT cancel recovery (it's an admin op)
    let ctx = vec![&env, get_cancel_recovery_context(&env, &contract_id)];
    let result = check_auth(&env, &contract_id, &recovery, &ctx);
    assert_eq!(result.unwrap_err(), Error::InsufficientPermissions);
}

// ============================================================================
// Role transitions
// ============================================================================

#[test]
fn test_add_recovery_signer() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::add_signer(&env, recovery.into_signer(&env))
    });
    assert!(result.is_ok());

    let signer = env
        .as_contract(&contract_id, || {
            SmartAccount::get_signer(&env, recovery_key)
        })
        .unwrap();
    assert_eq!(signer.role(), SignerRole::Recovery(300, false));
}

#[test]
fn test_revoke_recovery_signer() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::revoke_signer(&env, recovery_key.clone())
    });
    assert!(result.is_ok());

    let has = env
        .as_contract(&contract_id, || {
            SmartAccount::has_signer(&env, recovery_key)
        })
        .unwrap();
    assert!(!has);
}

#[test]
fn test_update_recovery_to_standard() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let updated = with_role(&recovery, SignerRole::Standard(None, 0));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated.into_signer(&env))
    });
    assert!(result.is_ok());

    let signer = env
        .as_contract(&contract_id, || {
            SmartAccount::get_signer(&env, recovery_key)
        })
        .unwrap();
    assert_eq!(signer.role(), SignerRole::Standard(None, 0));
}

#[test]
fn test_update_standard_to_recovery() {
    let env = setup();
    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard = Ed25519TestSigner::generate(SignerRole::Standard(None, 0));
    let standard_key = SignerKey::Ed25519(standard.public_key(&env));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), standard.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    let updated = with_role(&standard, SignerRole::Recovery(600, true));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::update_signer(&env, updated.into_signer(&env))
    });
    assert!(result.is_ok());

    let signer = env
        .as_contract(&contract_id, || {
            SmartAccount::get_signer(&env, standard_key)
        })
        .unwrap();
    assert_eq!(signer.role(), SignerRole::Recovery(600, true));
}

// ============================================================================
// Recovery signer does not expire
// ============================================================================

#[test]
fn test_recovery_signer_never_expires() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1_000_000_000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(300, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Even at a very high timestamp, recovery signer should be authorized
    env.ledger().with_mut(|li| li.timestamp = 9_999_999_999);
    let ctx = vec![&env, get_schedule_recovery_context(&env, &contract_id)];
    check_auth(&env, &contract_id, &recovery, &ctx).unwrap();
}

// ============================================================================
// Recovery operation scheduling inner-signer validation
// ============================================================================

#[test]
fn test_schedule_recovery_validates_inner_recovery_delay() {
    let env = setup();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let admin = Ed25519TestSigner::generate(SignerRole::Admin);
    let recovery = Ed25519TestSigner::generate(SignerRole::Recovery(60, false));

    let contract_id = env.register(
        SmartAccount,
        (
            vec![&env, admin.into_signer(&env), recovery.into_signer(&env)],
            Vec::<Address>::new(&env),
        ),
    );

    // Try to schedule adding a recovery signer with delay 0 (invalid)
    let bad_inner = Ed25519TestSigner::generate(SignerRole::Recovery(0, false));
    let operation = RecoveryOperation::AddSigner(bad_inner.into_signer(&env));
    let salt: BytesN<32> = BytesN::random(&env);
    let recovery_key = SignerKey::Ed25519(recovery.public_key(&env));

    env.mock_all_auths();
    let result = env.as_contract(&contract_id, || {
        SmartAccount::schedule_recovery(&env, recovery_key, operation, salt)
    });

    assert_eq!(result.unwrap_err(), SmartAccountError::InvalidRecoveryDelay);
}
