use soroban_sdk::BytesN;

use crate::auth::signature::SignerProof;

pub trait ProofValidation {
    fn validate(&self, payload: &BytesN<32>, proof: SignerProof) -> bool;
}
