mod ed25519;
pub mod secp256r1;

pub use ed25519::Ed25519Signer;
pub use secp256r1::Secp256r1Signer;

use crate::auth::proof::SignerProof;
use crate::error::Error;
use soroban_sdk::{BytesN, Env};

pub trait SignatureVerifier {
    /// Verify a signature against a payload
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error>;
}
