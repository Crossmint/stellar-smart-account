#![cfg(test)]

extern crate std;

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer as _;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use soroban_sdk::xdr::{
    HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, ToXdr, WriteXdr,
};
use soroban_sdk::{contract, contractimpl, map, Address, Bytes, BytesN, Env, Vec};
use stellar_strkey::{ed25519, Strkey};

use super::*;
use crate::signer::{Signature, SignerExpiration, SignerLimits};

// ============================================================================
// Test Constants
// ============================================================================

const DEFAULT_NONCE: i64 = 3;
const TEST_SEED_PREFIX: &str = "test_seed_";

// ============================================================================
// Test Contract (for testing authorization)
// ============================================================================

#[contract]
pub struct ExampleContract;

#[contractimpl]
impl ExampleContract {
    pub fn deploy(env: Env, source: Address, wasm_hash: BytesN<32>) {
        env.deployer()
            .with_address(source, wasm_hash.clone())
            .deploy_v2(wasm_hash, ());
    }

    pub fn call(_env: Env, from: Address) {
        from.require_auth();
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

struct TestEnvironment<'a> {
    env: Env,
    smart_wallet_address: Address,
    smart_wallet_client: SmartWalletClient<'a>,
    example_contract_address: Address,
    example_contract_client: ExampleContractClient<'a>,
}

impl<'a> TestEnvironment<'a> {
    fn new_with_signer(seed: &str) -> (Self, Signer, Keypair) {
        let env = Env::default();
        let (signer, keypair) = create_keypair_signer(&env, seed);
        let signers = Vec::from_slice(&env, &[signer.clone()]);

        let smart_wallet_address = env.register(SmartWallet, (signers,));
        let smart_wallet_client = SmartWalletClient::new(&env, &smart_wallet_address);

        let example_contract_address = env.register(ExampleContract, ());
        let example_contract_client = ExampleContractClient::new(&env, &example_contract_address);

        (
            TestEnvironment {
                env,
                smart_wallet_address,
                smart_wallet_client,
                example_contract_address,
                example_contract_client,
            },
            signer,
            keypair,
        )
    }

    fn new_with_signers(signers: Vec<Signer>) -> Self {
        let env = Env::default();
        let smart_wallet_address = env.register(SmartWallet, (signers,));
        let smart_wallet_client = SmartWalletClient::new(&env, &smart_wallet_address);

        let example_contract_address = env.register(ExampleContract, ());
        let example_contract_client = ExampleContractClient::new(&env, &example_contract_address);

        TestEnvironment {
            env,
            smart_wallet_address,
            smart_wallet_client,
            example_contract_address,
            example_contract_client,
        }
    }
}

fn create_keypair_signer(env: &Env, seed: &str) -> (Signer, Keypair) {
    let seed_bytes = env
        .crypto()
        .sha256(&Bytes::from_slice(env, seed.as_bytes()));
    let mut rng: StdRng = SeedableRng::from_seed(seed_bytes.into());
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let keypair = Keypair::generate(&mut rng);

    let ed25519_strkey = Strkey::PublicKeyEd25519(ed25519::PublicKey(keypair.public.to_bytes()));
    let ed25519_address_bytes = Bytes::from_slice(env, ed25519_strkey.to_string().as_bytes());
    let ed25519_address = Address::from_string_bytes(&ed25519_address_bytes);

    let ed25519_bytes = ed25519_address.to_xdr(env);
    let ed25519_bytes = ed25519_bytes.slice(ed25519_bytes.len() - 32..);
    let mut ed25519_array = [0u8; 32];
    ed25519_bytes.copy_into_slice(&mut ed25519_array);
    let ed25519_bytes = BytesN::from_array(env, &ed25519_array);

    let signer = Signer::Ed25519(ed25519_bytes, SignerExpiration(None), SignerLimits(None));

    (signer, keypair)
}

fn create_signature(env: &Env, keypair: &Keypair, payload: &BytesN<32>) -> Signature {
    let signature_bytes = keypair.sign(payload.to_array().as_slice()).to_bytes();
    Signature::Ed25519(BytesN::from_array(env, &signature_bytes))
}

fn create_authorization_payload(
    env: &Env,
    contract_address: &Address,
    function_name: &str,
    args: std::vec::Vec<soroban_sdk::xdr::ScVal>,
    nonce: i64,
    signature_expiration_ledger: u32,
) -> BytesN<32> {
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract_address.clone().try_into().unwrap(),
            function_name: function_name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };

    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: env.ledger().network_id().to_array().into(),
        nonce,
        signature_expiration_ledger,
        invocation: root_invocation,
    });

    let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
    let payload_bytes = Bytes::from_slice(env, payload_xdr.as_slice());
    env.crypto().sha256(&payload_bytes).into()
}

fn create_authorization_entry(
    env: &Env,
    wallet_address: &Address,
    contract_address: &Address,
    function_name: &str,
    args: std::vec::Vec<soroban_sdk::xdr::ScVal>,
    signer_key: &SignerKey,
    signature: &Signature,
    nonce: i64,
    signature_expiration_ledger: u32,
) -> SorobanAuthorizationEntry {
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract_address.clone().try_into().unwrap(),
            function_name: function_name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: wallet_address.clone().try_into().unwrap(),
            nonce,
            signature_expiration_ledger,
            signature: Signatures(map![env, (signer_key.clone(), signature.clone())])
                .try_into()
                .unwrap(),
        }),
        root_invocation,
    }
}

fn get_signer_key_from_signer(signer: &Signer) -> SignerKey {
    match signer {
        Signer::Ed25519(bytes, _, _) => SignerKey::Ed25519(bytes.clone()),
    }
}

// ============================================================================
// Constructor Tests
// ============================================================================

#[test]
fn test_constructor_with_single_signer() {
    let env = Env::default();
    let (signer, _) = create_keypair_signer(&env, "constructor_single");
    let signers = Vec::from_slice(&env, &[signer]);
    let _deployed_address = env.register(SmartWallet, (signers,));
}

#[test]
fn test_constructor_with_multiple_signers() {
    let env = Env::default();
    let (signer1, _) = create_keypair_signer(&env, "constructor_multi_1");
    let (signer2, _) = create_keypair_signer(&env, "constructor_multi_2");
    let signers = Vec::from_slice(&env, &[signer1, signer2]);
    let _deployed_address = env.register(SmartWallet, (signers,));
}

#[test]
#[should_panic]
fn test_constructor_rejects_duplicate_signers() {
    let env = Env::default();
    let (signer, _) = create_keypair_signer(&env, "constructor_duplicate");
    let signers = Vec::from_slice(&env, &[signer.clone(), signer.clone()]);
    env.register(SmartWallet, (signers,));
}

#[test]
#[should_panic]
fn test_constructor_rejects_empty_signers() {
    let env = Env::default();
    let signers = Vec::<Signer>::from_slice(&env, &[]);
    env.register(SmartWallet, (signers,));
}

// ============================================================================
// Signer Management Tests (Mocked Auth)
// ============================================================================

#[test]
fn test_add_signer_with_mock_auth() {
    let (test_env, _signer, _keypair) = TestEnvironment::new_with_signer("add_signer_mock");
    let (new_signer, _) = create_keypair_signer(&test_env.env, "add_signer_mock_new");

    test_env
        .smart_wallet_client
        .mock_all_auths()
        .add_signer(&new_signer);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_add_signer_rejects_duplicate_with_mock_auth() {
    let (test_env, signer, _keypair) = TestEnvironment::new_with_signer("add_duplicate_mock");

    test_env
        .smart_wallet_client
        .mock_all_auths()
        .add_signer(&signer);
}

// ============================================================================
// Real Authorization Tests
// ============================================================================

#[test]
fn test_external_contract_call_with_real_auth() {
    let (test_env, signer, keypair) = TestEnvironment::new_with_signer("external_call_real");
    let signature_expiration_ledger = test_env.env.ledger().sequence();

    let payload = create_authorization_payload(
        &test_env.env,
        &test_env.example_contract_address,
        "call",
        std::vec![test_env.smart_wallet_address.clone().try_into().unwrap()],
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    let signature = create_signature(&test_env.env, &keypair, &payload);
    let signer_key = get_signer_key_from_signer(&signer);

    let auth_entry = create_authorization_entry(
        &test_env.env,
        &test_env.smart_wallet_address,
        &test_env.example_contract_address,
        "call",
        std::vec![test_env.smart_wallet_address.clone().try_into().unwrap()],
        &signer_key,
        &signature,
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    test_env
        .example_contract_client
        .set_auths(&[auth_entry])
        .call(&test_env.smart_wallet_address);
}

#[test]
fn test_add_signer_with_real_auth() {
    let (test_env, signer, keypair) = TestEnvironment::new_with_signer("add_signer_real");
    let (new_signer, _) = create_keypair_signer(&test_env.env, "add_signer_real_new");
    let signature_expiration_ledger = test_env.env.ledger().sequence();

    let payload = create_authorization_payload(
        &test_env.env,
        &test_env.smart_wallet_address,
        "add_signer",
        std::vec![new_signer.clone().try_into().unwrap()],
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    let signature = create_signature(&test_env.env, &keypair, &payload);
    let signer_key = get_signer_key_from_signer(&signer);

    let auth_entry = create_authorization_entry(
        &test_env.env,
        &test_env.smart_wallet_address,
        &test_env.smart_wallet_address,
        "add_signer",
        std::vec![new_signer.clone().try_into().unwrap()],
        &signer_key,
        &signature,
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    test_env
        .smart_wallet_client
        .set_auths(&[auth_entry])
        .add_signer(&new_signer);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_add_signer_rejects_invalid_signature() {
    let (test_env, signer, keypair) = TestEnvironment::new_with_signer("add_signer_invalid");
    let (new_signer, _) = create_keypair_signer(&test_env.env, "add_signer_invalid_new");
    let signature_expiration_ledger = test_env.env.ledger().sequence();

    let payload = create_authorization_payload(
        &test_env.env,
        &test_env.smart_wallet_address,
        "add_signer",
        std::vec![new_signer.clone().try_into().unwrap()],
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    // Create invalid signature by modifying payload
    let mut invalid_payload = payload.to_array();
    invalid_payload[0] = invalid_payload[0].wrapping_add(1);
    let invalid_payload = BytesN::from_array(&test_env.env, &invalid_payload);

    let invalid_signature = create_signature(&test_env.env, &keypair, &invalid_payload);
    let signer_key = get_signer_key_from_signer(&signer);

    let auth_entry = create_authorization_entry(
        &test_env.env,
        &test_env.smart_wallet_address,
        &test_env.smart_wallet_address,
        "add_signer",
        std::vec![new_signer.clone().try_into().unwrap()],
        &signer_key,
        &invalid_signature,
        DEFAULT_NONCE,
        signature_expiration_ledger,
    );

    test_env
        .smart_wallet_client
        .set_auths(&[auth_entry])
        .add_signer(&new_signer);
}
