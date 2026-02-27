//! Tests for upgrading from v1.0.0 to v2 and migrating on-chain state.
//!
//! These tests use pre-built WASM binaries:
//! - v1: from the v1.0.0 GitHub release (optimized)
//! - v2: built from the current source code

extern crate alloc;
extern crate std;

use soroban_sdk::auth::Context;
use soroban_sdk::{
    auth::ContractContext, contract, contractimpl, map, symbol_short, testutils::BytesN as _, vec,
    Address, Bytes, BytesN, Env, IntoVal, Symbol, Vec,
};

use crate::auth::proof::{SignatureProofs, SignerProof};
use crate::error::Error;
use crate::tests::test_utils::get_token_auth_context;

// A minimal external-policy contract so the v1 constructor's `on_add` call succeeds.
#[contract]
pub struct DummyExternalPolicy;

#[contractimpl]
impl DummyExternalPolicy {
    pub fn on_add(_env: &Env, source: Address) {
        source.require_auth();
    }

    pub fn on_revoke(_env: &Env, source: Address) {
        source.require_auth();
    }

    pub fn is_authorized(_env: &Env, source: Address, _contexts: Vec<Context>) -> bool {
        source.require_auth();
        true
    }
}

// Import v1 WASM — generates v1::WASM, v1::Client, and v1-era types from the contract spec
mod v1 {
    #![allow(unused)]
    use soroban_sdk::auth::Context;
    soroban_sdk::contractimport!(file = "testdata/smart_account_v1.wasm");
}

// Import v2 WASM — generates v2::WASM, v2::Client, and v2-era types (including MigrationData)
mod v2 {
    #![allow(unused)]
    use soroban_sdk::auth::Context;
    soroban_sdk::contractimport!(file = "testdata/smart_account_v2.wasm");
}

// ============================================================================
// Helper functions
// ============================================================================

/// Generate an Ed25519 keypair for test use.
fn generate_ed25519_keypair() -> ed25519_dalek::Keypair {
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    ed25519_dalek::Keypair::generate(&mut StdRng::from_entropy())
}

/// Deploy a v1 contract with a single Ed25519 admin signer.
/// Returns (contract_address, keypair).
fn deploy_v1_with_ed25519_admin(env: &Env) -> (Address, ed25519_dalek::Keypair) {
    let keypair = generate_ed25519_keypair();
    let pk = BytesN::from_array(env, &keypair.public.to_bytes());

    let signer = v1::Signer::Ed25519(v1::Ed25519Signer { public_key: pk }, v1::SignerRole::Admin);

    let contract_id = env.register(v1::WASM, (vec![env, signer], Vec::<Address>::new(env)));

    (contract_id, keypair)
}

/// Deploy a v1 contract with an Ed25519 admin and a Secp256r1 (WebAuthn) signer.
/// Returns (contract_address, admin_keypair, secp_key_id, secp_public_key_bytes).
fn deploy_v1_with_secp256r1_signer(
    env: &Env,
) -> (Address, ed25519_dalek::Keypair, [u8; 18], [u8; 65]) {
    let admin_keypair = generate_ed25519_keypair();
    let admin_pk = BytesN::from_array(env, &admin_keypair.public.to_bytes());

    let admin_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: admin_pk,
        },
        v1::SignerRole::Admin,
    );

    // Generate a P-256 keypair for WebAuthn signer
    use p256::ecdsa::SigningKey;
    let sk_bytes = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        bytes[31] = 1;
        bytes
    };
    let signing_key = SigningKey::from_bytes(&sk_bytes.into()).expect("valid signing key");
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let mut pk_bytes = [0u8; 65];
    pk_bytes.copy_from_slice(encoded.as_bytes());

    let key_id: [u8; 18] = *b"test_credential_id";

    let secp_signer = v1::Signer::Secp256r1(
        v1::Secp256r1Signer {
            key_id: Bytes::from_array(env, &key_id),
            public_key: BytesN::from_array(env, &pk_bytes),
        },
        v1::SignerRole::Admin,
    );

    let contract_id = env.register(
        v1::WASM,
        (
            vec![env, admin_signer, secp_signer],
            Vec::<Address>::new(env),
        ),
    );

    (contract_id, admin_keypair, key_id, pk_bytes)
}

/// Upload v2 WASM and return its hash.
fn upload_v2_wasm(env: &Env) -> BytesN<32> {
    env.deployer()
        .upload_contract_wasm(Bytes::from_slice(env, v2::WASM))
}

/// Creates a Context::Contract representing a call to `upgrade(new_wasm_hash)` on the
/// smart account itself. Because this is a self-call, the permission logic in
/// `permissions.rs` treats it as requiring admin approval.
fn get_upgrade_auth_context(e: &Env, contract_id: &Address, new_wasm_hash: BytesN<32>) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "upgrade".into_val(e),
        args: (new_wasm_hash,).into_val(e),
    })
}

/// Creates a Context::Contract representing a call to `migrate(migration_data)` on the
/// smart account itself.
fn get_migrate_auth_context(
    e: &Env,
    contract_id: &Address,
    migration_data: v2::MigrationData,
) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "migrate".into_val(e),
        args: (migration_data,).into_val(e),
    })
}

// ============================================================================
// Test: Ed25519 admin signer preserved after upgrade
// ============================================================================

#[test]
fn test_upgrade_ed25519_admin_preserved() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, keypair) = deploy_v1_with_ed25519_admin(&env);
    let pk = BytesN::from_array(&env, &keypair.public.to_bytes());

    // Verify signer exists on v1
    let v1_client = v1::Client::new(&env, &contract_id);
    let v1_signer = v1_client.get_signer(&v1::SignerKey::Ed25519(pk.clone()));
    assert!(matches!(
        v1_signer,
        v1::Signer::Ed25519(_, v1::SignerRole::Admin)
    ));

    // Upgrade to v2
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate with empty list (no signers need migration)
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));

    // Verify signer still accessible after upgrade
    let v2_signer = v2_client.get_signer(&v2::SignerKey::Ed25519(pk));
    assert!(matches!(
        v2_signer,
        v2::Signer::Ed25519(_, v2::SignerRole::Admin)
    ));
}

// ============================================================================
// Test: Secp256r1 signer migrated to Webauthn
// ============================================================================

#[test]
fn test_migrate_secp256r1_to_webauthn() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _admin_keypair, key_id, pk_bytes) = deploy_v1_with_secp256r1_signer(&env);

    // Verify secp256r1 signer exists on v1
    let v1_client = v1::Client::new(&env, &contract_id);
    let v1_signer =
        v1_client.get_signer(&v1::SignerKey::Secp256r1(Bytes::from_array(&env, &key_id)));
    assert!(matches!(
        v1_signer,
        v1::Signer::Secp256r1(_, v1::SignerRole::Admin)
    ));

    // Upgrade to v2
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate: tell the contract about the Secp256r1 signer that needs conversion
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![
            &env,
            v2::V1SignerKey::Secp256r1(Bytes::from_array(&env, &key_id)),
        ],
    }));

    // Verify: old Secp256r1 key should NOT exist anymore
    let has_old = v2_client.has_signer(&v2::SignerKey::Secp256r1(BytesN::from_array(
        &env, &pk_bytes,
    )));
    assert!(!has_old);

    // Verify: new Webauthn key SHOULD exist
    let new_signer =
        v2_client.get_signer(&v2::SignerKey::Webauthn(Bytes::from_array(&env, &key_id)));
    match new_signer {
        v2::Signer::Webauthn(webauthn_signer, v2::SignerRole::Admin) => {
            assert_eq!(webauthn_signer.key_id, Bytes::from_array(&env, &key_id));
            assert_eq!(
                webauthn_signer.public_key,
                BytesN::from_array(&env, &pk_bytes)
            );
        }
        other => panic!("Expected Webauthn signer, got {:?}", other),
    }
}

// ============================================================================
// Test: Empty migration for Ed25519-only accounts
// ============================================================================

#[test]
fn test_upgrade_empty_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _keypair) = deploy_v1_with_ed25519_admin(&env);

    // Upgrade
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate with empty list
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));

    // Contract should work fine — verify with is_deployed
    assert!(v2_client.is_deployed());
}

// ============================================================================
// Test: Migrate cannot be called without prior upgrade
// ============================================================================

#[test]
#[should_panic(expected = "Error(Contract, #1100)")]
fn test_migrate_without_upgrade_fails() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy v2 directly (no upgrade path)
    let keypair = generate_ed25519_keypair();
    let pk = BytesN::from_array(&env, &keypair.public.to_bytes());

    let signer = v2::Signer::Ed25519(v2::Ed25519Signer { public_key: pk }, v2::SignerRole::Admin);

    let contract_id = env.register(v2::WASM, (vec![&env, signer], Vec::<Address>::new(&env)));

    // Try to call migrate without upgrade — should fail with MigrationNotAllowed (1100)
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));
}

// ============================================================================
// Test: Migrate cannot be called twice
// ============================================================================

#[test]
#[should_panic(expected = "Error(Contract, #1100)")]
fn test_migrate_cannot_run_twice() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _keypair) = deploy_v1_with_ed25519_admin(&env);

    // Upgrade
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // First migrate — should succeed
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));

    // Second migrate — should fail with MigrationNotAllowed (1100)
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));
}

// ============================================================================
// Test: New signer types work after upgrade
// ============================================================================

#[test]
fn test_new_signer_types_after_upgrade() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _keypair) = deploy_v1_with_ed25519_admin(&env);

    // Upgrade and migrate
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    }));

    // Add a new Webauthn signer (not possible on v1)
    let webauthn_key_id = Bytes::from_slice(&env, b"new_webauthn_key");
    let pk_bytes: [u8; 65] = {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04; // uncompressed point marker
        bytes[1] = 0xAA;
        bytes[64] = 0xBB;
        bytes
    };
    let webauthn_signer = v2::Signer::Webauthn(
        v2::WebauthnSigner {
            key_id: webauthn_key_id.clone(),
            public_key: BytesN::from_array(&env, &pk_bytes),
        },
        v2::SignerRole::Admin,
    );
    v2_client.add_signer(&webauthn_signer);

    // Verify it was added
    let retrieved = v2_client.get_signer(&v2::SignerKey::Webauthn(webauthn_key_id));
    assert!(matches!(
        retrieved,
        v2::Signer::Webauthn(_, v2::SignerRole::Admin)
    ));
}

// ============================================================================
// Test: v1 admin count preserved after migration
// ============================================================================

#[test]
fn test_upgrade_preserves_admin_count() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, admin_keypair, _key_id, _pk_bytes) = deploy_v1_with_secp256r1_signer(&env);

    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    // v1: two admin signers (Ed25519 + Secp256r1)
    // Upgrade to v2
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate the secp256r1 signer
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![
            &env,
            v2::V1SignerKey::Secp256r1(Bytes::from_array(&env, &_key_id)),
        ],
    }));

    // Both signers should still exist (Ed25519 as Ed25519, old Secp256r1 as Webauthn)
    let ed25519_signer = v2_client.get_signer(&v2::SignerKey::Ed25519(admin_pk));
    assert!(matches!(
        ed25519_signer,
        v2::Signer::Ed25519(_, v2::SignerRole::Admin)
    ));

    let webauthn_signer =
        v2_client.get_signer(&v2::SignerKey::Webauthn(Bytes::from_array(&env, &_key_id)));
    assert!(matches!(
        webauthn_signer,
        v2::Signer::Webauthn(_, v2::SignerRole::Admin)
    ));
}

// ============================================================================
// Test: Ed25519 standard signer with external policy migrated
// ============================================================================

#[test]
fn test_migrate_ed25519_with_external_policy() {
    let env = Env::default();
    env.mock_all_auths();

    let admin_keypair = generate_ed25519_keypair();
    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    let standard_keypair = generate_ed25519_keypair();
    let standard_pk = BytesN::from_array(&env, &standard_keypair.public.to_bytes());

    // Deploy a mock policy contract so v1 constructor's `on_add` succeeds
    let policy_address = env.register(DummyExternalPolicy, ());

    let admin_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: admin_pk,
        },
        v1::SignerRole::Admin,
    );

    let standard_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: standard_pk.clone(),
        },
        v1::SignerRole::Standard(vec![
            &env,
            v1::SignerPolicy::ExternalValidatorPolicy(v1::ExternalPolicy {
                policy_address: policy_address.clone(),
            }),
        ]),
    );

    let contract_id = env.register(
        v1::WASM,
        (
            vec![&env, admin_signer, standard_signer],
            Vec::<Address>::new(&env),
        ),
    );

    // Upgrade to v2
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate — ALL Standard signers need migration due to XDR layout change
    // (v1 Standard(Vec<...>) vs v2 Standard(Option<Vec<...>>, u64))
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env, v2::V1SignerKey::Ed25519(standard_pk.clone())],
    }));

    // Verify the standard signer and its policy are preserved
    let signer = v2_client.get_signer(&v2::SignerKey::Ed25519(standard_pk));
    match signer {
        v2::Signer::Ed25519(_, v2::SignerRole::Standard(Some(policies), expiration)) => {
            assert_eq!(policies.len(), 1);
            assert_eq!(expiration, 0);
        }
        other => panic!("Expected Ed25519 Standard signer, got {:?}", other),
    }
}

// ============================================================================
// Test: Ed25519 with TimeWindowPolicy needs migration
// ============================================================================

#[test]
fn test_migrate_ed25519_with_time_window_policy() {
    let env = Env::default();
    env.mock_all_auths();

    let admin_keypair = generate_ed25519_keypair();
    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    let standard_keypair = generate_ed25519_keypair();
    let standard_pk = BytesN::from_array(&env, &standard_keypair.public.to_bytes());

    let admin_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: admin_pk,
        },
        v1::SignerRole::Admin,
    );

    // Create standard signer with TimeWindowPolicy (variant removed in v2)
    let standard_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: standard_pk.clone(),
        },
        v1::SignerRole::Standard(vec![
            &env,
            v1::SignerPolicy::TimeWindowPolicy(v1::TimeBasedPolicy {
                not_before: 0,
                not_after: u64::MAX,
            }),
        ]),
    );

    let contract_id = env.register(
        v1::WASM,
        (
            vec![&env, admin_signer, standard_signer],
            Vec::<Address>::new(&env),
        ),
    );

    // Upgrade to v2
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    // Migrate — the Ed25519 standard signer with TimeWindowPolicy needs migration
    // because the TimeWindowPolicy variant no longer exists in v2
    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env, v2::V1SignerKey::Ed25519(standard_pk.clone())],
    }));

    // Verify signer exists and TimeWindowPolicy was dropped
    let signer = v2_client.get_signer(&v2::SignerKey::Ed25519(standard_pk));
    match signer {
        v2::Signer::Ed25519(_, v2::SignerRole::Standard(None, expiration)) => {
            // TimeWindowPolicy should have been dropped during migration, resulting in None
            assert_eq!(expiration, 0);
        }
        other => panic!(
            "Expected Ed25519 Standard signer with no policies, got {:?}",
            other
        ),
    }
}

// ############################################################################
// Post-migration functional tests
// ############################################################################
//
// These tests verify that the full contract functionality works correctly
// after a v1→v2 upgrade+migrate, not just that signers are preserved.

// A minimal plugin contract for post-migration plugin tests.
const PLUGIN_COUNT: Symbol = symbol_short!("plg_cnt");

#[contract]
pub struct DummyPlugin;

#[contractimpl]
impl DummyPlugin {
    pub fn on_install(_env: &Env, _source: Address) {}
    pub fn on_uninstall(_env: &Env, _source: Address) {}
    pub fn on_auth(env: &Env, _source: Address, _contexts: Vec<Context>) {
        let count: u32 = env.storage().instance().get(&PLUGIN_COUNT).unwrap_or(0);
        env.storage().instance().set(&PLUGIN_COUNT, &(count + 1));
    }
    pub fn get_count(env: &Env) -> u32 {
        env.storage().instance().get(&PLUGIN_COUNT).unwrap_or(0)
    }
}

/// Helper: deploy v1, upgrade to v2, and migrate.
/// Returns (contract_id, admin_keypair, v2_client).
fn upgrade_and_migrate(env: &Env) -> (Address, ed25519_dalek::Keypair, v2::Client<'_>) {
    let (contract_id, keypair) = deploy_v1_with_ed25519_admin(env);
    let v1_client = v1::Client::new(env, &contract_id);
    let v2_hash = upload_v2_wasm(env);
    v1_client.upgrade(&v2_hash);
    let v2_client = v2::Client::new(env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![env],
    }));
    (contract_id, keypair, v2_client)
}

// ============================================================================
// Test: Real Ed25519 signature verification works after migration
// ============================================================================

#[test]
fn test_auth_ed25519_works_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, admin_keypair, _v2_client) = upgrade_and_migrate(&env);

    // Build a real Ed25519 signature (no mock_all_auths for __check_auth)
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        admin_keypair.sign(payload.to_array().as_slice()).to_bytes()
    };

    let signer_key = smart_account_interfaces::SignerKey::Ed25519(BytesN::from_array(
        &env,
        &admin_keypair.public.to_bytes(),
    ));
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    // Invoke __check_auth with a real signature against the migrated contract
    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();
}

// ============================================================================
// Test: Add and revoke signers after migration
// ============================================================================

#[test]
fn test_add_and_revoke_signer_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (_contract_id, _admin_keypair, v2_client) = upgrade_and_migrate(&env);

    // Add a new standard signer
    let new_keypair = generate_ed25519_keypair();
    let new_pk = BytesN::from_array(&env, &new_keypair.public.to_bytes());
    let new_signer = v2::Signer::Ed25519(
        v2::Ed25519Signer {
            public_key: new_pk.clone(),
        },
        v2::SignerRole::Standard(None, 0),
    );
    v2_client.add_signer(&new_signer);

    // Verify the new signer exists
    assert!(v2_client.has_signer(&v2::SignerKey::Ed25519(new_pk.clone())));

    // Revoke the standard signer
    v2_client.revoke_signer(&v2::SignerKey::Ed25519(new_pk.clone()));

    // Verify it's gone
    assert!(!v2_client.has_signer(&v2::SignerKey::Ed25519(new_pk)));
}

// ============================================================================
// Test: Update signer role after migration
// ============================================================================

#[test]
fn test_update_signer_role_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (_contract_id, admin_keypair, v2_client) = upgrade_and_migrate(&env);
    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    // Add a second admin so we can downgrade the first one
    let admin2_keypair = generate_ed25519_keypair();
    let admin2_pk = BytesN::from_array(&env, &admin2_keypair.public.to_bytes());
    v2_client.add_signer(&v2::Signer::Ed25519(
        v2::Ed25519Signer {
            public_key: admin2_pk,
        },
        v2::SignerRole::Admin,
    ));

    // Downgrade first admin to standard
    v2_client.update_signer(&v2::Signer::Ed25519(
        v2::Ed25519Signer {
            public_key: admin_pk.clone(),
        },
        v2::SignerRole::Standard(None, 0),
    ));

    // Verify the role changed
    let signer = v2_client.get_signer(&v2::SignerKey::Ed25519(admin_pk));
    assert!(matches!(
        signer,
        v2::Signer::Ed25519(_, v2::SignerRole::Standard(_, _))
    ));
}

// ============================================================================
// Test: Install and use plugin after migration
// ============================================================================

#[test]
fn test_install_plugin_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, admin_keypair, v2_client) = upgrade_and_migrate(&env);

    // Deploy and install a plugin
    let plugin_id = env.register(DummyPlugin, ());
    v2_client.install_plugin(&plugin_id);

    // Verify plugin is installed
    assert!(v2_client.is_plugin_installed(&plugin_id));

    // Trigger real __check_auth to verify the plugin's on_auth is called
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        admin_keypair.sign(payload.to_array().as_slice()).to_bytes()
    };
    let signer_key = smart_account_interfaces::SignerKey::Ed25519(BytesN::from_array(
        &env,
        &admin_keypair.public.to_bytes(),
    ));
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![&env, get_token_auth_context(&env)],
    )
    .unwrap();

    // Verify the plugin received the on_auth callback
    let count = env.as_contract(&plugin_id, || DummyPlugin::get_count(&env));
    assert_eq!(
        count, 1,
        "Plugin should have received on_auth after migration"
    );

    // Uninstall the plugin
    v2_client.uninstall_plugin(&plugin_id);
    assert!(!v2_client.is_plugin_installed(&plugin_id));
}

// ============================================================================
// Test: Cannot revoke last admin after migration
// ============================================================================

#[test]
fn test_admin_protection_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (_contract_id, admin_keypair, v2_client) = upgrade_and_migrate(&env);
    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    // Try to revoke the only admin — contract should reject this
    // revoke_signer returns a Result; on the v2::Client it panics on error
    let result = v2_client.try_revoke_signer(&v2::SignerKey::Ed25519(admin_pk));
    assert!(
        result.is_err(),
        "Should not be able to revoke the last admin"
    );
}

// ============================================================================
// Test: Revoke migrated Webauthn signer (was standard on v1)
// ============================================================================

#[test]
fn test_revoke_migrated_webauthn_standard_signer() {
    let env = Env::default();
    env.mock_all_auths();

    let admin_keypair = generate_ed25519_keypair();
    let admin_pk = BytesN::from_array(&env, &admin_keypair.public.to_bytes());

    let admin_signer = v1::Signer::Ed25519(
        v1::Ed25519Signer {
            public_key: admin_pk,
        },
        v1::SignerRole::Admin,
    );

    // Create a secp256r1 signer as Standard role
    use p256::ecdsa::SigningKey;
    let sk_bytes = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x99;
        bytes[31] = 1;
        bytes
    };
    let signing_key = SigningKey::from_bytes(&sk_bytes.into()).expect("valid signing key");
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let mut pk_bytes = [0u8; 65];
    pk_bytes.copy_from_slice(encoded.as_bytes());
    let key_id: [u8; 18] = *b"standard_cred_abcd";

    let secp_signer = v1::Signer::Secp256r1(
        v1::Secp256r1Signer {
            key_id: Bytes::from_array(&env, &key_id),
            public_key: BytesN::from_array(&env, &pk_bytes),
        },
        v1::SignerRole::Standard(vec![&env]),
    );

    let contract_id = env.register(
        v1::WASM,
        (
            vec![&env, admin_signer, secp_signer],
            Vec::<Address>::new(&env),
        ),
    );

    // Upgrade and migrate
    let v1_client = v1::Client::new(&env, &contract_id);
    let v2_hash = upload_v2_wasm(&env);
    v1_client.upgrade(&v2_hash);

    let v2_client = v2::Client::new(&env, &contract_id);
    v2_client.migrate(&v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![
            &env,
            v2::V1SignerKey::Secp256r1(Bytes::from_array(&env, &key_id)),
        ],
    }));

    // Verify the migrated Webauthn signer exists and is Standard
    let webauthn_key = v2::SignerKey::Webauthn(Bytes::from_array(&env, &key_id));
    let signer = v2_client.get_signer(&webauthn_key);
    assert!(matches!(
        signer,
        v2::Signer::Webauthn(_, v2::SignerRole::Standard(_, _))
    ));

    // Revoke the migrated standard Webauthn signer
    v2_client.revoke_signer(&webauthn_key);

    // Verify it's gone
    assert!(!v2_client.has_signer(&webauthn_key));
}

// ############################################################################
// Post-migration auth enforcement tests
// ############################################################################
//
// These tests verify that __check_auth properly enforces admin-only access
// for upgrade and migrate contexts after a v1→v2 migration, using real
// Ed25519 signatures (not mock_all_auths).

// ============================================================================
// Test: Admin can authorize upgrade context after migration
// ============================================================================

#[test]
fn test_auth_admin_can_authorize_upgrade_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, admin_keypair, _v2_client) = upgrade_and_migrate(&env);

    // Build a real Ed25519 signature
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        admin_keypair.sign(payload.to_array().as_slice()).to_bytes()
    };

    let signer_key = smart_account_interfaces::SignerKey::Ed25519(BytesN::from_array(
        &env,
        &admin_keypair.public.to_bytes(),
    ));
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    let dummy_wasm_hash = BytesN::random(&env);

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![
            &env,
            get_upgrade_auth_context(&env, &contract_id, dummy_wasm_hash),
        ],
    )
    .unwrap();
}

// ============================================================================
// Test: Standard signer cannot authorize upgrade context after migration
// ============================================================================

#[test]
fn test_auth_standard_cannot_authorize_upgrade_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _admin_keypair, v2_client) = upgrade_and_migrate(&env);

    // Add a standard signer
    let standard_keypair = generate_ed25519_keypair();
    let standard_pk = BytesN::from_array(&env, &standard_keypair.public.to_bytes());
    let standard_signer = v2::Signer::Ed25519(
        v2::Ed25519Signer {
            public_key: standard_pk.clone(),
        },
        v2::SignerRole::Standard(None, 0),
    );
    v2_client.add_signer(&standard_signer);

    // Build a real Ed25519 signature from the standard signer
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        standard_keypair
            .sign(payload.to_array().as_slice())
            .to_bytes()
    };

    let signer_key = smart_account_interfaces::SignerKey::Ed25519(standard_pk);
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    let dummy_wasm_hash = BytesN::random(&env);

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![
                &env,
                get_upgrade_auth_context(&env, &contract_id, dummy_wasm_hash),
            ],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InsufficientPermissions),
    }
}

// ============================================================================
// Test: Admin can authorize migrate context after migration
// ============================================================================

#[test]
fn test_auth_admin_can_authorize_migrate_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, admin_keypair, _v2_client) = upgrade_and_migrate(&env);

    // Build a real Ed25519 signature
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        admin_keypair.sign(payload.to_array().as_slice()).to_bytes()
    };

    let signer_key = smart_account_interfaces::SignerKey::Ed25519(BytesN::from_array(
        &env,
        &admin_keypair.public.to_bytes(),
    ));
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    let migration_data = v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    });

    env.try_invoke_contract_check_auth::<Error>(
        &contract_id,
        &payload,
        auth_payloads.into_val(&env),
        &vec![
            &env,
            get_migrate_auth_context(&env, &contract_id, migration_data),
        ],
    )
    .unwrap();
}

// ============================================================================
// Test: Standard signer cannot authorize migrate context after migration
// ============================================================================

#[test]
fn test_auth_standard_cannot_authorize_migrate_after_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let (contract_id, _admin_keypair, v2_client) = upgrade_and_migrate(&env);

    // Add a standard signer
    let standard_keypair = generate_ed25519_keypair();
    let standard_pk = BytesN::from_array(&env, &standard_keypair.public.to_bytes());
    let standard_signer = v2::Signer::Ed25519(
        v2::Ed25519Signer {
            public_key: standard_pk.clone(),
        },
        v2::SignerRole::Standard(None, 0),
    );
    v2_client.add_signer(&standard_signer);

    // Build a real Ed25519 signature from the standard signer
    let payload = BytesN::random(&env);
    let signature_bytes = {
        use ed25519_dalek::Signer as _;
        standard_keypair
            .sign(payload.to_array().as_slice())
            .to_bytes()
    };

    let signer_key = smart_account_interfaces::SignerKey::Ed25519(standard_pk);
    let proof = SignerProof::Ed25519(BytesN::from_array(&env, &signature_bytes));
    let auth_payloads = SignatureProofs(map![&env, (signer_key, proof)]);

    let migration_data = v2::MigrationData::V1ToV2(v2::V1ToV2MigrationData {
        signers_to_migrate: vec![&env],
    });

    match env
        .try_invoke_contract_check_auth::<Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![
                &env,
                get_migrate_auth_context(&env, &contract_id, migration_data),
            ],
        )
        .unwrap_err()
    {
        Err(err) => panic!("{:?}", err),
        Ok(err) => assert_eq!(err, Error::InsufficientPermissions),
    }
}
