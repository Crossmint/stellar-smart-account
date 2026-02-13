mod ed25519;
mod multisig;
pub mod secp256r1;
pub mod webauthn;

use crate::auth::proof::SignerProof;
use crate::error::Error;
use soroban_sdk::{crypto::Hash, Env};

pub trait SignatureVerifier {
    /// Verify a signature against a payload hash
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error>;
}
