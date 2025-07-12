use soroban_sdk::{contracttype, BytesN, Map};

use crate::auth::signer::SignerKey;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerProof {
    Ed25519(BytesN<64>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationPayloads(pub Map<SignerKey, SignerProof>);
