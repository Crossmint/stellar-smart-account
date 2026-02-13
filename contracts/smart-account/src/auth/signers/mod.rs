mod ed25519;
mod multisig;
pub mod secp256r1;

use crate::auth::proof::SignerProof;
use crate::error::Error;
use soroban_sdk::{BytesN, Env};

pub trait SignatureVerifier {
    /// Verify a signature against a payload
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error>;
}
