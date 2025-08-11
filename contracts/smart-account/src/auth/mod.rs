/// This module exports the basic functionality for the Smart Account auth system
///
/// ## Core Objects and Classes
///
/// ### SignerPolicy
/// An enum that wraps individual policy implementations for restricted signers, including external delegation.
///
/// ### SignerRole
/// Defines the authorization level and restrictions for a signer:
/// - `Admin` - Can authorize any operation, including changing signers and upgrading contracts
/// - `Standard(Vec<SignerPolicy>)` - Can authorize any operation except changing signers and upgrading contracts; subject to policy restrictions if policies are provided (all policies must pass), including external policies
///
/// ### SignatureProofs
/// A wrapper struct containing a Map<SignerKey, SignerProof> that pairs signer keys with their
/// cryptographic proofs. Used to bundle authorization data for multi-signature operations.
///
/// ### SignerProof
/// An enum representing cryptographic proofs (e.g. signatures) for signature verification
///
/// ### SignerKey
/// An enum representing an identifier for different signature schemes:
///
/// ### Signer
/// The main signer enum that combines a cryptographic signer with a role:
///
/// ## Core Traits
///
/// ### AuthorizationCheck
/// Core trait for authorization checking. Implementations must provide:
/// - `is_authorized(&self, env: &Env, context: &Context) -> bool` - Determines if an operation
///   is authorized based on the execution context.
///
/// ### SignatureVerifier
/// Trait for cryptographic signature verification. Implementations must provide:
/// - `verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error>`
///   Verifies a signature proof against a payload hash. Used by Signer and specific signer types.
///
/// ### PolicyCallback
/// Trait for validating initialization parameters in signing policies. Implementations must provide:
/// - `check(&self, env: &Env) -> Result<(), Error>` - Validates that policy parameters are
///   correct and feasible at initialization time. Used by SignerPolicy and policy implementations.
///
/// ## Architecture
///
/// The auth system is designed with a layered approach:
/// 1. **Signers** combine cryptographic verification with role-based permissions
/// 2. **Roles** define what operations a signer can perform
/// 3. **Policies** add additional restrictions for Standard role signers when specified
/// 4. **Proofs** provide cryptographic evidence for authorization
///
/// This allows for flexible authorization schemes from simple admin access to complex
/// multi-signature accounts with time-based and contract-specific restrictions.
pub mod core;
pub mod permissions;
pub mod policy;
pub mod proof;
pub mod signer;
pub mod signers;
pub mod providers {
    pub use super::signers::*;
}
