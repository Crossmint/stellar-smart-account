use soroban_sdk::contracttype;
#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerExpiration(pub Option<u32>);
