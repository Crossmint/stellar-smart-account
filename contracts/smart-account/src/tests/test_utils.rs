#![cfg(test)]

extern crate alloc;
extern crate std;

use alloc::vec::Vec;

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use soroban_sdk::auth::Context;
use soroban_sdk::BytesN;
use soroban_sdk::Env;

use crate::auth::proof::SignerProof;
use smart_account_interfaces::SignerRole;
use smart_account_interfaces::{Ed25519Signer, Signer, SignerKey};

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
    #[allow(clippy::wrong_self_convention)]
    fn into_signer(&self, env: &Env) -> Signer;
    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof);
}

// ============================================================================
// Ed25519
// ============================================================================

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

    #[allow(clippy::wrong_self_convention)]
    fn into_signer(&self, env: &Env) -> Signer {
        let Ed25519TestSigner(_keypair, role) = self;
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

// ============================================================================
// Secp256r1 (raw)
// ============================================================================

use p256::ecdsa::{
    signature::hazmat::PrehashSigner, Signature as P256Signature, SigningKey, VerifyingKey,
};
use smart_account_interfaces::Secp256r1Signer;

/// Normalize an ECDSA signature to low-S form as required by Soroban.
fn normalize_signature(sig: &P256Signature) -> P256Signature {
    sig.normalize_s().unwrap_or_else(|| sig.clone())
}

use std::sync::atomic::{AtomicU32, Ordering};

/// Monotonically increasing counter to produce unique deterministic seeds.
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

pub struct Secp256r1TestSigner(pub SigningKey, pub SignerRole);

impl Secp256r1TestSigner {
    pub fn public_key(&self, env: &Env) -> BytesN<65> {
        BytesN::from_array(env, &verifying_key_bytes(&self.0))
    }
}

impl TestSignerTrait for Secp256r1TestSigner {
    fn generate(role: SignerRole) -> Self {
        Self(generate_p256_signing_key(), role)
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_signer(&self, env: &Env) -> Signer {
        Signer::Secp256r1(Secp256r1Signer::new(self.public_key(env)), self.1.clone())
    }

    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof) {
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

// ============================================================================
// WebAuthn
// ============================================================================

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use soroban_sdk::Bytes;

use crate::auth::proof::WebauthnSignature;
use smart_account_interfaces::WebauthnSigner;

#[derive(Serialize)]
struct WebauthnClientData<'a> {
    #[serde(rename = "type")]
    ty: &'a str,
    challenge: &'a str,
    origin: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

pub struct WebauthnTestSigner {
    pub signing_key: SigningKey,
    pub key_id: [u8; 18],
    pub role: SignerRole,
}

impl WebauthnTestSigner {
    fn public_key_bytes(&self) -> [u8; 65] {
        verifying_key_bytes(&self.signing_key)
    }

    fn build_authenticator_data() -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(b"example.com"));
        auth_data.push(0x01); // user present flag
        auth_data.extend_from_slice(&42u32.to_be_bytes()); // counter
        auth_data
    }

    fn build_webauthn_proof(
        &self,
        env: &Env,
        payload: &BytesN<32>,
        challenge_override: Option<&str>,
    ) -> SignerProof {
        let real_challenge = Base64UrlUnpadded::encode_string(&payload.to_array());
        let challenge = match challenge_override {
            Some(c) => std::string::String::from(c),
            None => real_challenge,
        };

        let client_data = WebauthnClientData {
            ty: "webauthn.get",
            challenge: &challenge,
            origin: "https://example.com",
            cross_origin: None,
        };
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        let authenticator_data = Self::build_authenticator_data();

        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let signature: P256Signature =
            p256::ecdsa::signature::Signer::sign(&self.signing_key, &signed_data);
        let normalized = normalize_signature(&signature);

        SignerProof::Webauthn(WebauthnSignature {
            authenticator_data: Bytes::from_slice(env, &authenticator_data),
            client_data_json: Bytes::from_slice(env, &client_data_json),
            signature: BytesN::from_array(
                env,
                normalized.to_bytes().as_slice().try_into().unwrap(),
            ),
        })
    }

    /// Sign with a wrong challenge (for negative tests).
    pub fn sign_wrong_challenge(
        &self,
        env: &Env,
        payload: &BytesN<32>,
    ) -> (SignerKey, SignerProof) {
        let correct = Base64UrlUnpadded::encode_string(&payload.to_array());
        let wrong = std::format!("{}X", &correct[..correct.len() - 1]);
        let signer_key = SignerKey::Webauthn(Bytes::from_array(env, &self.key_id));
        let proof = self.build_webauthn_proof(env, payload, Some(&wrong));
        (signer_key, proof)
    }
}

impl TestSignerTrait for WebauthnTestSigner {
    fn generate(role: SignerRole) -> Self {
        Self {
            signing_key: generate_p256_signing_key(),
            key_id: *b"test_credential_id",
            role,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_signer(&self, env: &Env) -> Signer {
        Signer::Webauthn(
            WebauthnSigner::new(
                Bytes::from_array(env, &self.key_id),
                BytesN::from_array(env, &self.public_key_bytes()),
            ),
            self.role.clone(),
        )
    }

    fn sign(&self, env: &Env, payload: &BytesN<32>) -> (SignerKey, SignerProof) {
        let signer_key = SignerKey::Webauthn(Bytes::from_array(env, &self.key_id));
        let proof = self.build_webauthn_proof(env, payload, None);
        (signer_key, proof)
    }
}
