use initializable::Error as InitializableError;
use soroban_sdk::contracterror;
use storage::Error as StorageError;

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
    NotInitialized = 8,
    StorageEntryNotFound = 9,
    StorageEntryAlreadyExists = 10,
    InvalidProofType = 11,
}

impl From<InitializableError> for Error {
    fn from(e: InitializableError) -> Self {
        match e {
            InitializableError::AlreadyInitialized => Error::AlreadyInitialized,
            InitializableError::NotInitialized => Error::NotInitialized,
        }
    }
}

impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NotFound => Error::StorageEntryNotFound,
            StorageError::AlreadyExists => Error::StorageEntryAlreadyExists,
        }
    }
}
