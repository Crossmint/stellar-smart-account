use soroban_sdk::log;
use soroban_sdk::{contracttype, crypto::Hash, Address, BytesN, Env, Map, Vec};

/*
SingleSigner:
  - Ed25519(public_key, expiration, limits)
  - MultiSig(signers, threshold)
*/

/*
Signer:
  - SingleSigner(SingleSigner, role)
  - MultiSig(signers, role, threshold)
*/

use crate::error::Error;

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerExpiration(pub Option<u32>);
