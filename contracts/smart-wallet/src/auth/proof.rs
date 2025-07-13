use soroban_sdk::{contracttype, BytesN, Map};

use crate::auth::signer::SignerKey;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerProof {
    Ed25519(BytesN<64>),
    Secp256k1(BytesN<64>, u32),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureProofs(pub Map<SignerKey, SignerProof>);
