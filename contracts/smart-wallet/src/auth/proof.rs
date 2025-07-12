use soroban_sdk::{contracttype, BytesN, Map};

use crate::auth::signer::SignerKey;

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerProof {
    Ed25519(BytesN<64>),
}

pub type SignerProofEntry = (SignerKey, SignerProof);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationPayloads(pub Map<SignerKey, SignerProof>);
