use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SmartAccountError {
    AlreadyInitialized = 0,
    NotInitialized = 1,
    AccountInitializationFailed = 2,

    StorageEntryNotFound = 10,
    StorageEntryAlreadyExists = 11,

    NoSigners = 20,
    SignerAlreadyExists = 21,
    SignerNotFound = 22,
    SignerExpired = 23,
    CannotRevokeAdminSigner = 24,
    CannotDowngradeLastAdmin = 25,
    MaxSignersReached = 26,

    MatchingSignatureNotFound = 40,
    SignatureVerificationFailed = 41,
    InvalidProofType = 42,
    NoProofsInAuthEntry = 43,
    ClientDataJsonIncorrectChallenge = 44,
    InvalidWebauthnClientDataJson = 45,

    MultisigThresholdNotMet = 46,
    MultisigInvalidThreshold = 47,
    MultisigMemberNotFound = 48,

    InsufficientPermissions = 60,
    InsufficientPermissionsOnCreation = 61,

    InvalidPolicy = 80,
    InvalidTimeRange = 81,
    InvalidNotAfterTime = 82,
    PolicyClientInitializationError = 83,

    PluginNotFound = 100,
    PluginAlreadyInstalled = 101,
    PluginInitializationFailed = 102,
    PluginOnAuthFailed = 103,

    NotFound = 1000,
}

impl From<initializable::Error> for SmartAccountError {
    fn from(e: initializable::Error) -> Self {
        match e {
            initializable::Error::AlreadyInitialized => SmartAccountError::AlreadyInitialized,
            initializable::Error::NotInitialized => SmartAccountError::NotInitialized,
        }
    }
}

impl From<storage::Error> for SmartAccountError {
    fn from(e: storage::Error) -> Self {
        match e {
            storage::Error::NotFound => SmartAccountError::StorageEntryNotFound,
            storage::Error::AlreadyExists => SmartAccountError::StorageEntryAlreadyExists,
        }
    }
}
