use soroban_sdk::{contracttype, Address, Bytes, BytesN, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    Admin,
    Standard(Vec<SignerPolicy>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    ExternalValidatorPolicy(ExternalPolicy),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPolicy {
    pub policy_address: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
}

impl Ed25519Signer {
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

impl Secp256r1Signer {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

impl Signer {
    pub fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
            Signer::Secp256r1(_, role) => role.clone(),
        }
    }
}

impl From<Ed25519Signer> for SignerKey {
    fn from(signer: Ed25519Signer) -> Self {
        SignerKey::Ed25519(signer.public_key.clone())
    }
}

impl From<Secp256r1Signer> for SignerKey {
    fn from(signer: Secp256r1Signer) -> Self {
        SignerKey::Secp256r1(signer.key_id.clone())
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
            Signer::Secp256r1(signer, _) => signer.into(),
        }
    }
}
