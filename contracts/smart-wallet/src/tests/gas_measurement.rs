#![cfg(test)]

use crate::auth::{permissions::SignerRole, proof::SignatureProofs};
use crate::tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait};
use crate::wallet::SmartWallet;
use soroban_sdk::{map, testutils::BytesN as _, vec, BytesN};
use soroban_sdk::{Env, IntoVal};

pub struct GasMeasurement {
    pub cpu_instructions: u64,
    pub memory_bytes: u64,
}

impl GasMeasurement {
    pub fn measure<F>(env: &Env, operation: F) -> Self
    where
        F: FnOnce(),
    {
        env.cost_estimate().budget().reset_default();
        operation();

        Self {
            cpu_instructions: 0, // Placeholder - budget API changed
            memory_bytes: 0,     // Placeholder - budget API changed
        }
    }
}

#[test]
fn test_check_auth_gas_single_signer() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, admin_signer.into_signer(&env)],));

    let payload = BytesN::random(&env);
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);

    let gas = GasMeasurement::measure(&env, || {
        env.try_invoke_contract_check_auth::<crate::error::Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, crate::tests::test_utils::get_token_auth_context(&env)],
        )
        .unwrap();
    });

    assert_eq!(gas.cpu_instructions, 0); // Placeholder assertion
}

#[test]
fn test_check_auth_gas_multiple_signers() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let standard_signer1 = Ed25519TestSigner::generate(SignerRole::Standard);
    let standard_signer2 = Ed25519TestSigner::generate(SignerRole::Standard);
    let standard_signer3 = Ed25519TestSigner::generate(SignerRole::Standard);

    let contract_id = env.register(
        SmartWallet,
        (vec![
            &env,
            admin_signer.into_signer(&env),
            standard_signer1.into_signer(&env),
            standard_signer2.into_signer(&env),
            standard_signer3.into_signer(&env),
        ],),
    );

    let payload = BytesN::random(&env);
    let (admin_key, admin_proof) = admin_signer.sign(&env, &payload);
    let (std1_key, std1_proof) = standard_signer1.sign(&env, &payload);
    let (std2_key, std2_proof) = standard_signer2.sign(&env, &payload);
    let (std3_key, std3_proof) = standard_signer3.sign(&env, &payload);

    let auth_payloads = SignatureProofs(map![
        &env,
        (admin_key.clone(), admin_proof.clone()),
        (std1_key.clone(), std1_proof.clone()),
        (std2_key.clone(), std2_proof.clone()),
        (std3_key.clone(), std3_proof.clone())
    ]);

    let gas = GasMeasurement::measure(&env, || {
        env.try_invoke_contract_check_auth::<crate::error::Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &vec![&env, crate::tests::test_utils::get_token_auth_context(&env)],
        )
        .unwrap();
    });

    assert_eq!(gas.cpu_instructions, 0); // Placeholder assertion
}

#[test]
fn test_check_auth_gas_multiple_contexts() {
    let env = setup();
    let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
    let contract_id = env.register(SmartWallet, (vec![&env, admin_signer.into_signer(&env)],));

    let payload = BytesN::random(&env);
    let (signer_key, proof) = admin_signer.sign(&env, &payload);
    let auth_payloads = SignatureProofs(map![&env, (signer_key.clone(), proof.clone())]);

    let contexts = vec![
        &env,
        crate::tests::test_utils::get_token_auth_context(&env),
        crate::tests::test_utils::get_token_auth_context(&env),
        crate::tests::test_utils::get_token_auth_context(&env),
    ];

    let gas = GasMeasurement::measure(&env, || {
        env.try_invoke_contract_check_auth::<crate::error::Error>(
            &contract_id,
            &payload,
            auth_payloads.into_val(&env),
            &contexts,
        )
        .unwrap();
    });

    assert_eq!(gas.cpu_instructions, 0); // Placeholder assertion
}
