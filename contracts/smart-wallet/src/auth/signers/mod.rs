pub mod ed25519;

use crate::auth::signature::SignerProof;
use crate::error::Error;
use soroban_sdk::{BytesN, Env};

pub trait SignerVerification {
    /// Verify a signature against a payload
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error>;
}

pub trait Into<SignerKey> {
    fn into(&self) -> SignerKey;
}
