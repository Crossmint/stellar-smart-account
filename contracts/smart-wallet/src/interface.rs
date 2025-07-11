use soroban_sdk::{Env, Vec};

use crate::{
    error::Error,
    signer::{Signer, SignerKey},
};

pub trait SmartWalletInterface {
    fn __constructor(env: Env, signers: Vec<Signer>);
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn revoke_signer(env: &Env, signer: SignerKey) -> Result<(), Error>;
}
