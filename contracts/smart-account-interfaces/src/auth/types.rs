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
    Secp256r1(BytesN<65>),
    Webauthn(Bytes),
    Multisig(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct WebauthnSigner {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MultisigMember {
    Ed25519(Ed25519Signer),
    Secp256r1(Secp256r1Signer),
    Webauthn(WebauthnSigner),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MultisigSigner {
    pub id: BytesN<32>,
    pub members: Vec<MultisigMember>,
    pub threshold: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
    Webauthn(WebauthnSigner, SignerRole),
    Multisig(MultisigSigner, SignerRole),
}

impl Ed25519Signer {
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

impl Secp256r1Signer {
    pub fn new(public_key: BytesN<65>) -> Self {
        Self { public_key }
    }
}

impl WebauthnSigner {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

impl MultisigSigner {
    pub fn new(id: BytesN<32>, members: Vec<MultisigMember>, threshold: u32) -> Self {
        Self {
            id,
            members,
            threshold,
        }
    }
}

impl Signer {
    pub fn role(&self) -> SignerRole {
        match self {
            Signer::Ed25519(_, role) => role.clone(),
            Signer::Secp256r1(_, role) => role.clone(),
            Signer::Webauthn(_, role) => role.clone(),
            Signer::Multisig(_, role) => role.clone(),
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
        SignerKey::Secp256r1(signer.public_key.clone())
    }
}

impl From<WebauthnSigner> for SignerKey {
    fn from(signer: WebauthnSigner) -> Self {
        SignerKey::Webauthn(signer.key_id.clone())
    }
}

impl From<MultisigMember> for SignerKey {
    fn from(member: MultisigMember) -> Self {
        match member {
            MultisigMember::Ed25519(signer) => signer.into(),
            MultisigMember::Secp256r1(signer) => signer.into(),
            MultisigMember::Webauthn(signer) => signer.into(),
        }
    }
}

impl From<MultisigSigner> for SignerKey {
    fn from(signer: MultisigSigner) -> Self {
        SignerKey::Multisig(signer.id.clone())
    }
}

impl From<Signer> for SignerKey {
    fn from(signer: Signer) -> Self {
        match signer {
            Signer::Ed25519(signer, _) => signer.into(),
            Signer::Secp256r1(signer, _) => signer.into(),
            Signer::Webauthn(signer, _) => signer.into(),
            Signer::Multisig(signer, _) => signer.into(),
        }
    }
}
