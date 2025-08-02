use initializable::Error as InitializableError;
use soroban_sdk::contracterror;
use storage::Error as StorageError;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    // === Initialization Errors (0-9) ===
    /// Contract has already been initialized
    AlreadyInitialized = 0,
    /// Contract has not been initialized yet
    NotInitialized = 1,

    // === Storage Errors (10-19) ===
    /// Storage entry was not found
    StorageEntryNotFound = 10,
    /// Storage entry already exists
    StorageEntryAlreadyExists = 11,

    // === Signer Management Errors (20-39) ===
    /// No signers are configured for the account
    NoSigners = 20,
    /// Signer already exists in the account
    SignerAlreadyExists = 21,
    /// Signer was not found in the account
    SignerNotFound = 22,
    /// Signer has expired and is no longer valid
    SignerExpired = 23,
    CannotRevokeAdminSigner = 24,

    // === Authentication & Signature Errors (40-59) ===
    /// No matching signature found for the given criteria
    MatchingSignatureNotFound = 40,
    /// Signature verification failed during authentication
    SignatureVerificationFailed = 41,
    /// Invalid proof type provided
    InvalidProofType = 42,
    /// No proofs found in the authentication entry
    NoProofsInAuthEntry = 43,

    // === Permission Errors (60-79) ===
    /// Insufficient permissions to perform the requested operation
    InsufficientPermissions = 60,
    /// Insufficient permissions during account creation
    InsufficientPermissionsOnCreation = 61,

    // === Policy Errors (80-99) ===
    /// Invalid policy configuration
    InvalidPolicy = 80,
    /// Invalid time range specified in policy
    InvalidTimeRange = 81,
    /// Invalid not-after time specified
    InvalidNotAfterTime = 82,
    /// Policy client error
    PolicyClientInitializationError = 83,

    // === Module Errors (100-119) ===
    /// Module not found
    ModuleNotFound = 100,
    /// Module already exists
    ModuleAlreadyInstalled = 101,
    /// Module initialization failed
    ModuleInitializationFailed = 102,

    // === Generic Errors (1000+) ===
    /// Requested resource was not found
    NotFound = 1000,
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
