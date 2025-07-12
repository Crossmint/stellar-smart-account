#![cfg(test)]

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use soroban_sdk::BytesN;
use soroban_sdk::Env;

use crate::auth::signature::SignerProof;
use crate::auth::signature::SignerProofEntry;
use crate::auth::signer::Signer;
use crate::auth::signer::SignerKey;
use crate::auth::signers::ed25519::Ed25519Signer;

pub trait TestSigner {
    fn generate() -> Self;
    fn into_signer(&self, env: &Env) -> Signer;
    fn sign(&self, env: &Env, payload: &BytesN<32>) -> SignerProofEntry;
}

pub struct Ed25519TestSigner(pub Keypair);

impl Ed25519TestSigner {
    pub fn public_key(&self, env: &Env) -> BytesN<32> {
        let Ed25519TestSigner(keypair) = self;
        BytesN::from_array(env, &keypair.public.to_bytes())
    }
}

impl TestSigner for Ed25519TestSigner {
    fn generate() -> Self {
        Self(Keypair::generate(&mut StdRng::from_entropy()))
    }

    fn into_signer(&self, env: &Env) -> Signer {
        Signer::Ed25519(Ed25519Signer::new(self.public_key(env)))
    }

    fn sign(&self, env: &Env, payload: &BytesN<32>) -> SignerProofEntry {
        let signature_bytes = self.0.sign(payload.to_array().as_slice()).to_bytes();
        if signature_bytes.len() != 64 {
            panic!("Invalid signature length");
        }
        let signer_key = SignerKey::Ed25519(BytesN::from_array(env, &self.0.public.to_bytes()));
        let signature = SignerProof::Ed25519(BytesN::from_array(env, &signature_bytes));
        (signer_key, signature)
    }
}
