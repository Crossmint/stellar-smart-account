use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, Vec};

// === ABI Types mirrored from the smart-account contract ===

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPolicy {
    pub policy_address: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPolicy {
    ExternalValidatorPolicy(ExternalPolicy),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerRole {
    Admin,
    Standard(Vec<SignerPolicy>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signer {
    pub public_key: BytesN<32>,
}

impl Ed25519Signer {
    pub fn new(public_key: BytesN<32>) -> Self {
        Self { public_key }
    }
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signer {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,
}

impl Secp256r1Signer {
    pub fn new(key_id: Bytes, public_key: BytesN<65>) -> Self {
        Self { key_id, public_key }
    }
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
}

// === Client interface for the Smart Account contract ===

#[contractclient(name = "SmartAccountClient")]
pub trait SmartAccount {
    fn __constructor(env: Env, signers: Vec<Signer>, plugins: Vec<Address>);

    fn add_signer(env: &Env, signer: Signer);
    fn update_signer(env: &Env, signer: Signer);
    fn revoke_signer(env: &Env, signer_key: SignerKey);

    fn get_signer(env: &Env, signer_key: SignerKey) -> Signer;
    fn has_signer(env: &Env, signer_key: SignerKey) -> bool;

    fn install_plugin(env: &Env, plugin: Address);
    fn uninstall_plugin(env: &Env, plugin: Address);
    fn is_plugin_installed(env: &Env, plugin: Address) -> bool;
}
