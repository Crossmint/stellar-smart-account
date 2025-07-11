use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    NoSigners = 0,
    NotFound = 1,
    MatchingSignatureNotFound = 2,
    SignatureVerificationFailed = 3,
    SignerExpired = 4,
    SignerAlreadyExists = 5,
    SignerNotFound = 6,
    AlreadyInitialized = 7,
}
