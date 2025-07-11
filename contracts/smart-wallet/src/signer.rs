use soroban_sdk::log;
use soroban_sdk::{
    contracttype, crypto::Hash, Address, BytesN, Env, Map, Vec,
};

use crate::error::Error;

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerExpiration(pub Option<u32>);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerLimits(pub Option<Map<Address, Option<Vec<SignerKey>>>>);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct Threshold(pub u32);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(BytesN<32>, SignerExpiration, SignerLimits),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(bytes, _, _) => SignerKey::Ed25519(bytes),
        }
    }
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerVal {
    Ed25519(SignerExpiration, SignerLimits),
}

impl From<Signer> for SignerVal {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(_, expiration, limits) => SignerVal::Ed25519(expiration, limits),
        }
    }
}

impl Signer {
    pub fn verify(&self, env: &Env, signed_payload: &SignedPayload) -> Result<(), Error> {
        log!(
            &env,
            "Verifying signature {:?} for payload {:?}",
            signed_payload.signature,
            signed_payload.signature_payload
        );
        match signed_payload.signature.clone() {
            Signature::Ed25519(signature) => {
                let Signer::Ed25519(public_key, _, _) = self;
                env.crypto().ed25519_verify(
                    public_key,
                    &signed_payload.signature_payload.clone().into(),
                    &signature,
                );
                Ok(())
            }
        }
    }
}

impl From<(SignerKey, SignerVal)> for Signer {
    fn from((signer_key, signer_val): (SignerKey, SignerVal)) -> Self {
        match signer_val {
            SignerVal::Ed25519(expiration, limits) => {
                let SignerKey::Ed25519(public_key) = signer_key;
                Signer::Ed25519(public_key, expiration, limits)
            }
        }
    }
}

pub struct SignedPayload {
    pub signature_payload: Hash<32>,
    pub signature: Signature,
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    Ed25519(BytesN<64>),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct Signatures(pub Map<SignerKey, Signature>);
