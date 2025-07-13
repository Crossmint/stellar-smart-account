use crate::auth::proof::SignerProof;
use crate::auth::signer::SignerKey;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MultisigSigner {
    pub public_keys: Vec<BytesN<32>>,
    pub threshold: u32,
}

impl MultisigSigner {
    pub fn new(public_keys: Vec<BytesN<32>>, threshold: u32) -> Result<Self, Error> {
        if public_keys.is_empty() {
            return Err(Error::EmptyPublicKeysList);
        }
        if threshold == 0 {
            return Err(Error::InvalidThreshold);
        }
        if threshold > public_keys.len() {
            return Err(Error::InvalidThreshold);
        }

        Ok(Self {
            public_keys,
            threshold,
        })
    }
}

impl SignatureVerifier for MultisigSigner {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Multisig(signatures) => {
                if signatures.len() < self.threshold {
                    return Err(Error::InsufficientSignatures);
                }

                let mut valid_signatures = 0u32;
                let payload_bytes = Bytes::from(payload.clone());

                for (index, signature) in signatures.iter() {
                    if index >= (self.public_keys.len() as u32) {
                        return Err(Error::InvalidSignerIndex);
                    }

                    let public_key = &self.public_keys.get(index).unwrap();

                    env.crypto()
                        .ed25519_verify(public_key, &payload_bytes, &signature);

                    valid_signatures += 1;
                }

                if valid_signatures >= self.threshold {
                    Ok(())
                } else {
                    Err(Error::InsufficientSignatures)
                }
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

impl From<MultisigSigner> for SignerKey {
    fn from(signer: MultisigSigner) -> Self {
        let mut data = Bytes::new(&signer.public_keys.env());

        data.append(&Bytes::from_array(
            &signer.public_keys.env(),
            &signer.threshold.to_be_bytes(),
        ));

        for key in signer.public_keys.iter() {
            data.append(&Bytes::from(key));
        }

        let hash = signer.public_keys.env().crypto().sha256(&data);
        SignerKey::Multisig(hash.into())
    }
}
