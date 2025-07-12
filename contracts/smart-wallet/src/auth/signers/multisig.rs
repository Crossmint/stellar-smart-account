use crate::auth::signer::SignerKey;
use crate::auth::signers::SignerVerification;
use crate::auth::{proof::SignerProof, signers::Ed25519Signer};
use crate::error::Error;
use soroban_sdk::{contracttype, BytesN, Env, Vec};

/// Ed25519 signer implementation
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MultiSigSigner {
    pub signers: Vec<BytesN<32>>,
    pub threshold: u32,
}

impl MultiSigSigner {
    /// Create a new MultiSig signer with the given signers and threshold
    pub fn new(signers: Vec<BytesN<32>>, threshold: u32) -> Self {
        Self { signers, threshold }
    }
}

impl SignerVerification for MultiSigSigner {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::MultiSig(proofs) => {
                let mut valid_signatures = 0;
                for (signer_key, proof) in proofs.iter() {
                    if valid_signatures >= self.threshold {
                        return Ok(());
                    }
                    match signer_key {
                        SignerKey::Ed25519(signer_key) => {
                            let signer = Ed25519Signer::new(signer_key.clone());
                            if self.signers.contains(signer_key) {
                                signer.verify(env, payload, &proof)?;
                                valid_signatures += 1;
                            }
                        }
                        _ => return Err(Error::InvalidProofType),
                    }
                }
                Ok(())
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

impl From<MultiSigSigner> for SignerKey {
    fn from(signer: MultiSigSigner) -> Self {
        SignerKey::MultiSig(signer.signers)
    }
}
