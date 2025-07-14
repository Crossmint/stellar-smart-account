use initializable::Error as InitializableError;
use soroban_sdk::contracterror;
use storage::Error as StorageError;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Contract has already been initialized
    AlreadyInitialized = 0,
    /// Contract has not been initialized yet
    NotInitialized = 1,

    /// Storage entry was not found
    StorageEntryNotFound = 10,
    /// Storage entry already exists
    StorageEntryAlreadyExists = 11,

    /// No signers are configured for the wallet
    NoSigners = 20,
    /// Signer already exists in the wallet
    SignerAlreadyExists = 21,
    /// Signer was not found in the wallet
    SignerNotFound = 22,
    /// Signer has expired and is no longer valid
    SignerExpired = 23,
    CannotRevokeAdminSigner = 24,
    /// Insufficient permissions during wallet creation
    InsufficientPermissionsOnCreation = 25,

    /// No matching signature found for the given criteria
    MatchingSignatureNotFound = 40,
    /// Signature verification failed during authentication
    SignatureVerificationFailed = 41,
    /// Invalid proof type provided
    InvalidProofType = 42,
    /// No proofs found in the authentication entry
    NoProofsInAuthEntry = 43,

    /// Insufficient permissions to perform the requested operation
    InsufficientPermissions = 60,

    /// Invalid policy configuration
    InvalidPolicy = 80,
    /// Invalid time range specified in policy
    InvalidTimeRange = 81,
    /// Invalid not-after time specified
    InvalidNotAfterTime = 82,

    /// Requested resource was not found
    NotFound = 100,
}

impl Error {
    pub fn is_initialization_error(&self) -> bool {
        matches!(self, Error::AlreadyInitialized | Error::NotInitialized)
    }

    pub fn is_storage_error(&self) -> bool {
        matches!(
            self,
            Error::StorageEntryNotFound | Error::StorageEntryAlreadyExists
        )
    }

    pub fn is_signer_management_error(&self) -> bool {
        matches!(
            self,
            Error::NoSigners
                | Error::SignerAlreadyExists
                | Error::SignerNotFound
                | Error::SignerExpired
                | Error::CannotRevokeAdminSigner
                | Error::InsufficientPermissionsOnCreation
        )
    }

    pub fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Error::MatchingSignatureNotFound
                | Error::SignatureVerificationFailed
                | Error::InvalidProofType
                | Error::NoProofsInAuthEntry
        )
    }

    pub fn is_permission_error(&self) -> bool {
        matches!(self, Error::InsufficientPermissions)
    }

    pub fn is_policy_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidPolicy | Error::InvalidTimeRange | Error::InvalidNotAfterTime
        )
    }

    pub fn is_generic_error(&self) -> bool {
        matches!(self, Error::NotFound)
    }

    pub fn domain(&self) -> &'static str {
        match self {
            Error::AlreadyInitialized | Error::NotInitialized => "Initialization",
            Error::StorageEntryNotFound | Error::StorageEntryAlreadyExists => "Storage",
            Error::NoSigners
            | Error::SignerAlreadyExists
            | Error::SignerNotFound
            | Error::SignerExpired
            | Error::CannotRevokeAdminSigner
            | Error::InsufficientPermissionsOnCreation => "SignerManagement",
            Error::MatchingSignatureNotFound
            | Error::SignatureVerificationFailed
            | Error::InvalidProofType
            | Error::NoProofsInAuthEntry => "Authentication",
            Error::InsufficientPermissions => "Permission",
            Error::InvalidPolicy | Error::InvalidTimeRange | Error::InvalidNotAfterTime => "Policy",
            Error::NotFound => "Generic",
        }
    }
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
