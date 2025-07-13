#![cfg(test)]

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;

extern crate alloc;
use alloc::vec::Vec;
use soroban_sdk::auth::Context;
use soroban_sdk::BytesN;
use soroban_sdk::Env;

use crate::auth::permissions::SignerRole;
use crate::auth::proof::SignerProof;
use crate::auth::signer::Signer;
use crate::auth::signer::SignerKey;
use crate::auth::signers::{Ed25519Signer, MultisigSigner};

use soroban_sdk::auth::ContractContext;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;
use soroban_sdk::IntoVal;

pub fn setup() -> Env {
    Env::default()
}

pub fn get_token_auth_context(e: &Env) -> Context {
    let token_address = Address::generate(e);
    Context::Contract(ContractContext {
        contract: token_address,
        fn_name: "transfer".into_val(e),
        args: ((), (), 1000).into_val(e),
    })
}

pub fn get_update_signer_auth_context(e: &Env, contract_id: &Address, signer: Signer) -> Context {
    Context::Contract(ContractContext {
        contract: contract_id.clone(),
        fn_name: "update_signer".into_val(e),
        args: (signer.clone(),).into_val(e),
    })
}

pub trait TestSignerTrait {
    fn generate(role: SignerRole) -> Self;
    fn into_signer(&self, env: &Env) -> Signer;
    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof);
}

pub struct Ed25519TestSigner(pub Keypair, pub SignerRole);

impl Ed25519TestSigner {
    pub fn public_key(&self, env: &Env) -> BytesN<32> {
        let Ed25519TestSigner(keypair, _) = self;
        BytesN::from_array(env, &keypair.public.to_bytes())
    }
}

impl TestSignerTrait for Ed25519TestSigner {
    fn generate(role: SignerRole) -> Self {
        Self(Keypair::generate(&mut StdRng::from_entropy()), role)
    }

    fn into_signer(&self, env: &Env) -> Signer {
        let Ed25519TestSigner(keypair, role) = self;
        Signer::Ed25519(Ed25519Signer::new(self.public_key(env)), role.clone())
    }

    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof) {
        let signature_bytes = self.0.sign(payload.to_array().as_slice()).to_bytes();
        if signature_bytes.len() != 64 {
            panic!("Invalid signature length");
        }
        let signer_key = SignerKey::Ed25519(BytesN::from_array(env, &self.0.public.to_bytes()));
        let signature = SignerProof::Ed25519(BytesN::from_array(env, &signature_bytes));
        (signer_key, signature)
    }
}

pub struct MultisigTestSigner(pub Vec<Keypair>, pub u32, pub SignerRole);

impl MultisigTestSigner {
    pub fn new(keypairs: Vec<Keypair>, threshold: u32, role: SignerRole) -> Self {
        Self(keypairs, threshold, role)
    }

    pub fn public_keys(&self, env: &Env) -> soroban_sdk::Vec<BytesN<32>> {
        let MultisigTestSigner(keypairs, _, _) = self;
        let mut keys = soroban_sdk::Vec::new(env);
        for keypair in keypairs {
            keys.push_back(BytesN::from_array(env, &keypair.public.to_bytes()));
        }
        keys
    }
}

impl TestSignerTrait for MultisigTestSigner {
    fn generate(role: SignerRole) -> Self {
        let mut keypairs = Vec::new();
        for _ in 0..3 {
            keypairs.push(Keypair::generate(&mut StdRng::from_entropy()));
        }
        Self(keypairs, 2, role)
    }

    fn into_signer(&self, env: &Env) -> Signer {
        let MultisigTestSigner(_, threshold, role) = self;
        let multisig_signer = MultisigSigner::new(self.public_keys(env), *threshold).unwrap();
        Signer::Multisig(multisig_signer, role.clone())
    }

    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof) {
        let MultisigTestSigner(keypairs, threshold, _) = self;
        let mut signatures = soroban_sdk::Map::new(env);

        for (i, keypair) in keypairs.iter().take(*threshold as usize).enumerate() {
            let signature_bytes = keypair.sign(payload.to_array().as_slice()).to_bytes();
            signatures.set(i as u32, BytesN::from_array(env, &signature_bytes));
        }

        let signer_key = self.into_signer(env).into();
        let proof = SignerProof::Multisig(signatures);
        (signer_key, proof)
    }
}
