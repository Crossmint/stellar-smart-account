use soroban_sdk::{Env, Vec};

use crate::auth::signer::{Signer, SignerKey};
use crate::error::Error;

pub trait SmartWalletInterface {
    fn __constructor(env: Env, signers: Vec<Signer>);

    // Admin operations
    fn add_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn update_signer(env: &Env, signer: Signer) -> Result<(), Error>;
    fn revoke_signer(env: &Env, signer: SignerKey) -> Result<(), Error>;
}
