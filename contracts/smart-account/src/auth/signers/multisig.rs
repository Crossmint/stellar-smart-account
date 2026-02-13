use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::{MultisigMember, MultisigSigner, SignerKey};
use soroban_sdk::{crypto::Hash, Env};

impl SignatureVerifier for MultisigMember {
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            MultisigMember::Ed25519(signer) => signer.verify(env, payload, proof),
            MultisigMember::Secp256r1(signer) => signer.verify(env, payload, proof),
            MultisigMember::Webauthn(signer) => signer.verify(env, payload, proof),
        }
    }
}

impl SignatureVerifier for MultisigSigner {
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error> {
        match proof {
            SignerProof::Multisig(member_proofs) => {
                let mut verified_count: u32 = 0;

                for (member_key, member_proof) in member_proofs.iter() {
                    let member = find_member(&self.members, &member_key)?;
                    member.verify(env, payload, &member_proof)?;
                    verified_count += 1;
                }

                if verified_count >= self.threshold {
                    Ok(())
                } else {
                    Err(Error::MultisigThresholdNotMet)
                }
            }
            _ => Err(Error::InvalidProofType),
        }
    }
}

fn find_member(
    members: &soroban_sdk::Vec<MultisigMember>,
    key: &SignerKey,
) -> Result<MultisigMember, Error> {
    for member in members.iter() {
        let member_key: SignerKey = member.clone().into();
        if member_key == *key {
            return Ok(member);
        }
    }
    Err(Error::MultisigMemberNotFound)
}
