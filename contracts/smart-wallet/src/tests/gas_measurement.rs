use crate::auth::{permissions::SignerRole, proof::SignatureProofs};
use crate::wallet::SmartWallet;
use soroban_sdk::{map, testutils::BytesN as _, vec, BytesN, Env, IntoVal};

#[cfg(test)]
use crate::tests::test_utils::{setup, Ed25519TestSigner, TestSignerTrait};

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
        
        let budget = env.cost_estimate().budget();
        Self {
            cpu_instructions: budget.cpu_instruction_cost(),
            memory_bytes: budget.memory_bytes_cost(),
        }
    }

    pub fn print_results(&self, test_name: &str) {
        println!("=== Gas Measurement Results for {} ===", test_name);
        println!("CPU Instructions: {}", self.cpu_instructions);
        println!("Memory Bytes: {}", self.memory_bytes);
        println!("==========================================");
    }

    pub fn to_json(&self, test_name: &str) -> String {
        format!(
            r#"{{"test_name": "{}", "cpu_instructions": {}, "memory_bytes": {}}}"#,
            test_name, self.cpu_instructions, self.memory_bytes
        )
    }
}

pub fn benchmark_check_auth_single_signer(env: &Env) -> GasMeasurement {
    #[cfg(test)]
    {
        let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
        let contract_id = env.register(SmartWallet, (vec![env, admin_signer.into_signer(env)],));
        
        let payload = BytesN::random(env);
        let (signer_key, proof) = admin_signer.sign(env, &payload);
        let auth_payloads = SignatureProofs(map![env, (signer_key.clone(), proof.clone())]);
        
        GasMeasurement::measure(env, || {
            env.try_invoke_contract_check_auth::<crate::error::Error>(
                &contract_id,
                &payload,
                auth_payloads.into_val(env),
                &vec![env, crate::tests::test_utils::get_token_auth_context(env)],
            ).unwrap();
        })
    }
    #[cfg(not(test))]
    {
        GasMeasurement {
            cpu_instructions: 0,
            memory_bytes: 0,
        }
    }
}

pub fn benchmark_check_auth_multiple_signers(env: &Env, signer_count: u32) -> GasMeasurement {
    #[cfg(test)]
    {
        let admin_signer = Ed25519TestSigner::generate(SignerRole::Admin);
        let mut signers = vec![env, admin_signer.into_signer(env)];
        let mut test_signers = vec![admin_signer];
        
        for _ in 1..signer_count {
            let signer = Ed25519TestSigner::generate(SignerRole::Standard);
            signers.push(signer.into_signer(env));
            test_signers.push(signer);
        }
        
        let contract_id = env.register(SmartWallet, (signers,));
        let payload = BytesN::random(env);
        
        let mut auth_map = map![env];
        for test_signer in &test_signers {
            let (key, proof) = test_signer.sign(env, &payload);
            auth_map.set(key, proof);
        }
        let auth_payloads = SignatureProofs(auth_map);
        
        GasMeasurement::measure(env, || {
            env.try_invoke_contract_check_auth::<crate::error::Error>(
                &contract_id,
                &payload,
                auth_payloads.into_val(env),
                &vec![env, crate::tests::test_utils::get_token_auth_context(env)],
            ).unwrap();
        })
    }
    #[cfg(not(test))]
    {
        GasMeasurement {
            cpu_instructions: 0,
            memory_bytes: 0,
        }
    }
}

pub fn run_all_benchmarks(env: &Env) {
    println!("Running Smart Wallet Gas Benchmarks...\n");
    
    let single_signer = benchmark_check_auth_single_signer(env);
    single_signer.print_results("Single Signer");
    
    let multiple_signers = benchmark_check_auth_multiple_signers(env, 4);
    multiple_signers.print_results("Multiple Signers (4)");
    
    println!("\nJSON Output:");
    println!("{}", single_signer.to_json("single_signer"));
    println!("{}", multiple_signers.to_json("multiple_signers_4"));
}

#[cfg(test)]

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
