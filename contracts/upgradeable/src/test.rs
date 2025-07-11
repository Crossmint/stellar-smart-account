#![cfg(test)]

use soroban_sdk::Env;

use crate::{can_complete_migration, complete_migration, enable_migration};

pub mod v1 {
    #[contracttype(export = false)]
    pub struct Signatures();

    #[contracterror]
    #[derive(Copy, Clone, Debug, PartialEq)]
    #[repr(u32)]
    pub enum Error {
        Error = 0,
    }

    use crate::{SmartWalletUpgradeable, SmartWalletUpgradeableAuth};
    use soroban_sdk::{
        auth::{Context, CustomAccountInterface},
        contract, contracterror, contractimpl, contracttype,
        crypto::Hash,
        log,
        xdr::String64,
        Env, String, Vec,
    };

    #[contract]
    pub struct ExampleWalletv1 {}
    impl SmartWalletUpgradeable for ExampleWalletv1 {}
    #[contractimpl]
    impl CustomAccountInterface for ExampleWalletv1 {
        type Signature = Signatures;
        type Error = Error;
        fn __check_auth(
            env: Env,
            signature_payload: Hash<32>,
            signatures: Signatures,
            auth_contexts: Vec<Context>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }
    #[contractimpl]
    impl ExampleWalletv1 {
        fn __constructor(env: Env) {}

        pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
            <Self as crate::SmartWalletUpgradeable>::upgrade(&env, new_wasm_hash);
        }

        pub fn only_in_v1(_env: Env) -> u32 {
            return 1;
        }

        pub fn in_both(_env: Env) -> u32 {
            return 1;
        }
    }
    impl SmartWalletUpgradeableAuth for ExampleWalletv1 {
        fn _require_auth_upgrade(_e: &Env) {}
    }
}

#[test]
fn test_contract_upgrade() {
    let env = Env::default();
    let contract_id_1 = env.register(v1::ExampleWalletv1 {}, ());
    env.as_contract(&contract_id_1, || {
        assert!(!can_complete_migration(&env));

        enable_migration(&env);
        assert!(can_complete_migration(&env));

        complete_migration(&env);
        assert!(!can_complete_migration(&env));
    });
}
