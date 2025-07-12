use soroban_sdk::contracttype;

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


#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerExpiration(pub Option<u32>);
