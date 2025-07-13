use soroban_sdk::{contracttype, BytesN, Map};

use crate::auth::signer::SignerKey;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerProof {
    Ed25519(BytesN<64>),
    Multisig(Map<u32, BytesN<64>>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureProofs(pub Map<SignerKey, SignerProof>);
