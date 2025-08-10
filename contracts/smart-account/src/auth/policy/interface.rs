use soroban_sdk::{auth::Context, contractclient, Address, Env, Vec};

#[contractclient(name = "SmartAccountPolicyClient")]
/// External policy interface for delegated authorization and lifecycle callbacks.
/// Failure policy:
/// - on_add: errors bubble to the caller and block signer addition/update.
/// - on_revoke: intended for cleanup on signer revocation; currently not invoked by SmartAccount.
/// - is_authorized: implementors should return false to deny; avoid panics to prevent unintended reverts.
pub trait SmartAccountPolicy {
    /// Called when a policy is added to a signer. Errors block the outer operation.
    fn on_add(env: &Env, source: Address);
    /// Called when a policy is removed from a signer. Not currently invoked by SmartAccount.
    fn on_revoke(env: &Env, source: Address);
    /// Returns true if the policy authorizes the provided contexts; false denies.
    fn is_authorized(env: &Env, source: Address, contexts: Vec<Context>) -> bool;
}
