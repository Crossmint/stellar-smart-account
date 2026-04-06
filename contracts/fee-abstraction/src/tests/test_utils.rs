extern crate std;

use p256::ecdsa::{
    signature::hazmat::PrehashSigner, Signature as P256Signature, SigningKey, VerifyingKey,
};
use smart_account::SignerProof;
use smart_account_interfaces::{Secp256r1Signer, Signer, SignerKey, SignerRole};
use soroban_sdk::{BytesN, Env};
use std::sync::atomic::{AtomicU32, Ordering};

static P256_SEED_COUNTER: AtomicU32 = AtomicU32::new(1);

fn generate_p256_signing_key() -> SigningKey {
    let seed = P256_SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut sk_bytes = [0u8; 32];
    sk_bytes[..4].copy_from_slice(&seed.to_be_bytes());
    sk_bytes[31] = 1; // ensure non-zero
    SigningKey::from_bytes(&sk_bytes.into()).expect("valid signing key")
}

fn verifying_key_bytes(signing_key: &SigningKey) -> [u8; 65] {
    let verifying_key = VerifyingKey::from(signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(encoded.as_bytes());
    pk
}

fn normalize_signature(sig: &P256Signature) -> P256Signature {
    sig.normalize_s().unwrap_or(*sig)
}

pub struct Secp256r1TestSigner(pub SigningKey, pub SignerRole);

impl Secp256r1TestSigner {
    pub fn generate(role: SignerRole) -> Self {
        Self(generate_p256_signing_key(), role)
    }

    pub fn public_key(&self, env: &Env) -> BytesN<65> {
        BytesN::from_array(env, &verifying_key_bytes(&self.0))
    }

    pub fn into_signer(&self, env: &Env) -> Signer {
        Signer::Secp256r1(Secp256r1Signer::new(self.public_key(env)), self.1.clone())
    }

    #[allow(dead_code)]
    pub fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof) {
        let signature: P256Signature = self
            .0
            .sign_prehash(&payload.to_array())
            .expect("secp256r1 signing");
        let normalized = normalize_signature(&signature);
        let signer_key = SignerKey::Secp256r1(self.public_key(env));
        let proof = SignerProof::Secp256r1(BytesN::from_array(
            env,
            normalized.to_bytes().as_slice().try_into().unwrap(),
        ));
        (signer_key, proof)
    }
}
