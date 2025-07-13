use soroban_sdk::{contracttype, Bytes, BytesN, Map};

use crate::auth::signer::SignerKey;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerProof {
    Ed25519(BytesN<64>),
    Secp256r1(Secp256r1Signature),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureProofs(pub Map<SignerKey, SignerProof>);
