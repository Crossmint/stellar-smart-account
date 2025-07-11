#![cfg(test)]

extern crate std;

use ed25519_dalek::Signer as __;
use soroban_sdk::testutils::Address as _;

use soroban_sdk::{contract, contractimpl, log, token, Address, BytesN, Env};

#[contract]
pub struct ExampleContract;

#[contractimpl]
impl ExampleContract {
    pub fn deploy(env: Env, source: Address, wasm_hash: BytesN<32>) {
        env.deployer()
            .with_address(source, wasm_hash.clone())
            .deploy_v2(wasm_hash, ());
    }
    pub fn call(env: Env, from: Address) {
        from.require_auth();
    }
}

use soroban_sdk::xdr::{
    HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, ToXdr, VecM,
};
use soroban_sdk::{map, Bytes};

use crate::signer::{Signature, SignerExpiration, SignerLimits};
use ed25519_dalek::Keypair;
use stellar_strkey::{ed25519, Strkey};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use soroban_sdk::xdr::WriteXdr;

use super::*;

fn create_keypair_signer(e: &Env, seed: &str) -> (Signer, Keypair) {
    let seed = e.crypto().sha256(&Bytes::from_slice(e, seed.as_bytes()));
    let mut rng: StdRng = SeedableRng::from_seed(seed.into());
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let keypair = Keypair::generate(&mut rng);

    let super_ed25519_strkey =
        Strkey::PublicKeyEd25519(ed25519::PublicKey(keypair.public.to_bytes()));
    let super_ed25519 = Bytes::from_slice(&e, super_ed25519_strkey.to_string().as_bytes());
    let super_ed25519 = Address::from_string_bytes(&super_ed25519);

    let super_ed25519_bytes = super_ed25519.to_xdr(&e);
    let super_ed25519_bytes = super_ed25519_bytes.slice(super_ed25519_bytes.len() - 32..);
    let mut super_ed25519_array = [0u8; 32];
    super_ed25519_bytes.copy_into_slice(&mut super_ed25519_array);
    let super_ed25519_bytes = BytesN::from_array(&e, &super_ed25519_array);

    (
        Signer::Ed25519(
            super_ed25519_bytes,
            SignerExpiration(None),
            SignerLimits(None),
        ),
        keypair,
    )
}

// ************
// Deploy Test
// ************

#[test]
fn test_constructor() {
    let e = Env::default();
    let (signer, _) = create_keypair_signer(&e, "test_constructor");
    let signers = Vec::from_slice(&e, &[signer]);
    let _depoyed_address = e.register(SmartWallet, (signers,));
}

#[test]
#[should_panic]
fn test_constructor_duplicate_signer() {
    let e = Env::default();
    let (signer, _) = create_keypair_signer(&e, "test_constructor_duplicate_signer");
    let signers = Vec::from_slice(&e, &[signer.clone(), signer.clone()]);
    e.register(SmartWallet, (signers,));
}

#[test]
#[should_panic]
fn test_constructor_no_signers() {
    let e = Env::default();
    let signers = Vec::<Signer>::from_slice(&e, &[]);
    e.register(SmartWallet, (signers,));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_invoke_add_duplicated_signer_no_auth() {
    let e = Env::default();
    let (signer, _) = create_keypair_signer(&e, "test_invoke_add_duplicated_signer_no_auth");
    let signers = Vec::from_slice(&e, &[signer.clone()]);
    let depoyed_address = e.register(SmartWallet, (signers,));
    let client = SmartWalletClient::new(&e, &depoyed_address);
    client.mock_all_auths().add_signer(&signer);
}

#[test]
fn test_invoke_add_signer_no_auth() {
    let e = Env::default();
    let (signer, _) = create_keypair_signer(&e, "test_invoke_add_signer_no_auth_1");
    let signers = Vec::from_slice(&e, &[signer.clone()]);
    let depoyed_address = e.register(SmartWallet, (signers,));
    let client = SmartWalletClient::new(&e, &depoyed_address);
    let (new_signer, _) = create_keypair_signer(&e, "test_invoke_add_signer_no_auth_2");
    client.mock_all_auths().add_signer(&new_signer);
}

#[test]
fn test_invoke_call_real_auth() {
    let e = Env::default();
    let signature_expiration_ledger = e.ledger().sequence();
    let seed = e.crypto().sha256(&Bytes::from_slice(
        &e,
        "test_invoke_call_real_auth".as_bytes(),
    ));
    let mut rng: StdRng = SeedableRng::from_seed(seed.into());
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let keypair = Keypair::generate(&mut rng);

    let super_ed25519_strkey =
        Strkey::PublicKeyEd25519(ed25519::PublicKey(keypair.public.to_bytes()));
    let super_ed25519 = Bytes::from_slice(&e, super_ed25519_strkey.to_string().as_bytes());
    let super_ed25519 = Address::from_string_bytes(&super_ed25519);

    let super_ed25519_bytes = super_ed25519.to_xdr(&e);
    let super_ed25519_bytes = super_ed25519_bytes.slice(super_ed25519_bytes.len() - 32..);
    let mut super_ed25519_array = [0u8; 32];
    super_ed25519_bytes.copy_into_slice(&mut super_ed25519_array);
    let super_ed25519_bytes = BytesN::from_array(&e, &super_ed25519_array);
    let super_ed25519_signer_key = SignerKey::Ed25519(super_ed25519_bytes.clone());
    let signer = Signer::Ed25519(
        super_ed25519_bytes,
        SignerExpiration(None),
        SignerLimits(None),
    );
    let signers = Vec::from_slice(&e, &[signer.clone()]);
    let depoyed_address = e.register(SmartWallet, (signers,));
    let example_contract_address = e.register(ExampleContract, ());
    let example_contract_client = ExampleContractClient::new(&e, &example_contract_address);
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: example_contract_address.clone().try_into().unwrap(),
            function_name: "call".try_into().unwrap(),
            args: std::vec![depoyed_address.clone().try_into().unwrap(),]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: e.ledger().network_id().to_array().into(),
        nonce: 3,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = payload.to_xdr(Limits::none()).unwrap();
    let payload = Bytes::from_slice(&e, payload.as_slice());
    let payload = e.crypto().sha256(&payload);
    let super_ed25519_signature = Signature::Ed25519(BytesN::from_array(
        &e,
        &keypair.sign(payload.to_array().as_slice()).to_bytes(),
    ));
    let root_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: depoyed_address.clone().try_into().unwrap(),
            nonce: 3,
            signature_expiration_ledger,
            signature: Signatures(map![
                &e,
                (super_ed25519_signer_key.clone(), super_ed25519_signature),
                // (
                //     sample_policy_signer_key.clone(),
                //     None
                // ),
                // (
                //     super_ed25519_signer_key.clone(),
                //     Some(super_ed25519_signature)
                // ),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: root_invocation.clone(),
    };
    example_contract_client
        .set_auths(&[root_auth])
        .call(&depoyed_address);
}

#[test]
fn test_invoke_add_signer_real_auth() {
    let e = Env::default();
    let signature_expiration_ledger = e.ledger().sequence();
    let seed = e.crypto().sha256(&Bytes::from_slice(
        &e,
        "test_invoke_add_signer_real_auth_1".as_bytes(),
    ));
    let mut rng: StdRng = SeedableRng::from_seed(seed.into());
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let keypair = Keypair::generate(&mut rng);

    let super_ed25519_strkey =
        Strkey::PublicKeyEd25519(ed25519::PublicKey(keypair.public.to_bytes()));
    let super_ed25519 = Bytes::from_slice(&e, super_ed25519_strkey.to_string().as_bytes());
    let super_ed25519 = Address::from_string_bytes(&super_ed25519);

    let super_ed25519_bytes = super_ed25519.to_xdr(&e);
    let super_ed25519_bytes = super_ed25519_bytes.slice(super_ed25519_bytes.len() - 32..);
    let mut super_ed25519_array = [0u8; 32];
    super_ed25519_bytes.copy_into_slice(&mut super_ed25519_array);
    let super_ed25519_bytes = BytesN::from_array(&e, &super_ed25519_array);
    let super_ed25519_signer_key = SignerKey::Ed25519(super_ed25519_bytes.clone());
    let signer = Signer::Ed25519(
        super_ed25519_bytes,
        SignerExpiration(None),
        SignerLimits(None),
    );
    let signers = Vec::from_slice(&e, &[signer.clone()]);
    let depoyed_address = e.register(SmartWallet, (signers,));
    let client = SmartWalletClient::new(&e, &depoyed_address);
    let (new_signer, _) = create_keypair_signer(&e, "test_invoke_add_signer_real_auth_2");
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: depoyed_address.clone().try_into().unwrap(),
            function_name: "add_signer".try_into().unwrap(),
            args: std::vec![new_signer.clone().try_into().unwrap()]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: e.ledger().network_id().to_array().into(),
        nonce: 3,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = payload.to_xdr(Limits::none()).unwrap();
    let payload = Bytes::from_slice(&e, payload.as_slice());
    let payload = e.crypto().sha256(&payload);
    let super_ed25519_signature = Signature::Ed25519(BytesN::from_array(
        &e,
        &keypair.sign(payload.to_array().as_slice()).to_bytes(),
    ));
    let root_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: depoyed_address.clone().try_into().unwrap(),
            nonce: 3,
            signature_expiration_ledger,
            signature: Signatures(map![
                &e,
                (super_ed25519_signer_key.clone(), super_ed25519_signature),
                // (
                //     sample_policy_signer_key.clone(),
                //     None
                // ),
                // (
                //     super_ed25519_signer_key.clone(),
                //     Some(super_ed25519_signature)
                // ),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: root_invocation.clone(),
    };
    client.set_auths(&[root_auth]).add_signer(&new_signer);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_invoke_add_signer_bad_auth() {
    let e = Env::default();
    let signature_expiration_ledger = e.ledger().sequence();
    let seed = e.crypto().sha256(&Bytes::from_slice(
        &e,
        "test_invoke_add_signer_real_auth_1".as_bytes(),
    ));
    let mut rng: StdRng = SeedableRng::from_seed(seed.into());
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let keypair = Keypair::generate(&mut rng);

    let super_ed25519_strkey =
        Strkey::PublicKeyEd25519(ed25519::PublicKey(keypair.public.to_bytes()));
    let super_ed25519 = Bytes::from_slice(&e, super_ed25519_strkey.to_string().as_bytes());
    let super_ed25519 = Address::from_string_bytes(&super_ed25519);

    let super_ed25519_bytes = super_ed25519.to_xdr(&e);
    let super_ed25519_bytes = super_ed25519_bytes.slice(super_ed25519_bytes.len() - 32..);
    let mut super_ed25519_array = [0u8; 32];
    super_ed25519_bytes.copy_into_slice(&mut super_ed25519_array);
    let super_ed25519_bytes = BytesN::from_array(&e, &super_ed25519_array);
    let super_ed25519_signer_key = SignerKey::Ed25519(super_ed25519_bytes.clone());
    let signer = Signer::Ed25519(
        super_ed25519_bytes,
        SignerExpiration(None),
        SignerLimits(None),
    );
    let signers = Vec::from_slice(&e, &[signer.clone()]);
    let depoyed_address = e.register(SmartWallet, (signers,));
    let client = SmartWalletClient::new(&e, &depoyed_address);
    let (new_signer, _) = create_keypair_signer(&e, "test_invoke_add_signer_real_auth_2");
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: depoyed_address.clone().try_into().unwrap(),
            function_name: "add_signer".try_into().unwrap(),
            args: std::vec![new_signer.clone().try_into().unwrap()]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: e.ledger().network_id().to_array().into(),
        nonce: 3,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = payload.to_xdr(Limits::none()).unwrap();
    let payload = Bytes::from_slice(&e, payload.as_slice());
    let payload = e.crypto().sha256(&payload);
    // Modify one byte to make signature invalid
    let mut modified_payload = payload.to_array();
    modified_payload[0] = modified_payload[0].wrapping_add(1);
    let modified_payload = BytesN::from_array(&e, &modified_payload);
    let super_ed25519_signature = Signature::Ed25519(BytesN::from_array(
        &e,
        &keypair
            .sign(modified_payload.to_array().as_slice())
            .to_bytes(),
    ));
    let root_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: depoyed_address.clone().try_into().unwrap(),
            nonce: 3,
            signature_expiration_ledger,
            signature: Signatures(map![
                &e,
                (
                    super_ed25519_signer_key.clone(),
                    super_ed25519_signature.clone()
                ),
                // (
                //     sample_policy_signer_key.clone(),
                //     None
                // ),
                // (
                //     super_ed25519_signer_key.clone(),
                //     Some(super_ed25519_signature)
                // ),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: root_invocation.clone(),
    };
    client.set_auths(&[root_auth]).add_signer(&new_signer);
}
