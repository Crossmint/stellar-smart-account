mod ed25519;

pub use ed25519::Ed25519Signer;

use crate::auth::proof::SignerProof;
use crate::error::Error;
use soroban_sdk::{BytesN, Env};

pub trait SignerVerification {
    /// Verify a signature against a payload
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error>;
}
