use soroban_sdk::{contracttype, Bytes, BytesN, Map};

use smart_account_interfaces::SignerKey;

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
    Multisig(Map<SignerKey, SignerProof>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureProofs(pub Map<SignerKey, SignerProof>);
