use crate::auth::permissions::AuthorizationCheck;
use crate::auth::proof::SignerProof;
use crate::auth::signers::SignatureVerifier;
use crate::error::Error;
use smart_account_interfaces::{
    Ed25519Signer, MultisigSigner, Secp256r1Signer, Signer, SignerKey, WebauthnSigner,
};
use soroban_sdk::Vec;
use soroban_sdk::{auth::Context, crypto::Hash, Env};

impl SignatureVerifier for Signer {
    fn verify(&self, env: &Env, payload: &Hash<32>, proof: &SignerProof) -> Result<(), Error> {
        match self {
            Signer::Ed25519(signer, _) => Ed25519Signer {
                public_key: signer.public_key.clone(),
            }
            .verify(env, payload, proof),
            Signer::Secp256r1(signer, _) => Secp256r1Signer {
                public_key: signer.public_key.clone(),
            }
            .verify(env, payload, proof),
            Signer::Webauthn(signer, _) => WebauthnSigner {
                key_id: signer.key_id.clone(),
                public_key: signer.public_key.clone(),
            }
            .verify(env, payload, proof),
            Signer::Multisig(signer, _) => MultisigSigner {
                id: signer.id.clone(),
                members: signer.members.clone(),
                threshold: signer.threshold,
            }
            .verify(env, payload, proof),
        }
    }
}

impl AuthorizationCheck for Signer {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool {
        self.role().is_authorized(env, signer_key, contexts)
    }
}
