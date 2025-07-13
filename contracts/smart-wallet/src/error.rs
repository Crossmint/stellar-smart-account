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
    /// No signers are configured for the wallet
    NoSigners = 20,
    /// Signer already exists in the wallet
    SignerAlreadyExists = 21,
    /// Signer was not found in the wallet
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
    /// Invalid threshold value for multisig signer
    InvalidThreshold = 44,
    EmptyPublicKeysList = 45,
    /// Insufficient signatures for multisig threshold
    InsufficientSignatures = 46,
    /// Invalid signer index in multisig proof
    InvalidSignerIndex = 47,

    // === Permission Errors (60-79) ===
    /// Insufficient permissions to perform the requested operation
    InsufficientPermissions = 60,
    /// Insufficient permissions during wallet creation
    InsufficientPermissionsOnCreation = 61,

    // === Policy Errors (80-99) ===
    /// Invalid policy configuration
    InvalidPolicy = 80,
    /// Invalid time range specified in policy
    InvalidTimeRange = 81,
    /// Invalid not-after time specified
    InvalidNotAfterTime = 82,

    // === Generic Errors (100+) ===
    /// Requested resource was not found
    NotFound = 100,
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
