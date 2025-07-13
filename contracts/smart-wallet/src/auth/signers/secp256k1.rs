use crate::auth::proof::SignerProof;
use crate::auth::signer::SignerKey;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use soroban_sdk::crypto::Hash;
use soroban_sdk::{contracttype, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256k1Signer {
    pub public_key: BytesN<33>,
}

impl Secp256k1Signer {
    pub fn new(public_key: BytesN<33>) -> Self {
        Self { public_key }
    }

    fn compress_public_key(&self, env: &Env, uncompressed_key: &BytesN<65>) -> BytesN<33> {
        let key_bytes = uncompressed_key.to_array();

        let x_coord = &key_bytes[1..33];
        let y_coord = &key_bytes[33..65];

        let y_is_even = y_coord[31] & 1 == 0;
        let prefix = if y_is_even { 0x02 } else { 0x03 };

        let mut compressed = [0u8; 33];
        compressed[0] = prefix;
        compressed[1..33].copy_from_slice(x_coord);

        BytesN::from_array(env, &compressed)
    }
}

impl SignatureVerifier for Secp256k1Signer {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Secp256k1(signature, recovery_id) => {
                let message_hash =
                    unsafe { core::mem::transmute::<BytesN<32>, Hash<32>>(payload.clone()) };

                let recovered_key =
                    env.crypto()
                        .secp256k1_recover(&message_hash, signature, *recovery_id);

                let compressed_key = self.compress_public_key(env, &recovered_key);

                if compressed_key == self.public_key {
                    Ok(())
                } else {
                    Err(Error::SignatureVerificationFailed)
                }
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

impl From<Secp256k1Signer> for SignerKey {
    fn from(signer: Secp256k1Signer) -> Self {
        SignerKey::Secp256k1(signer.public_key.clone())
    }
}
