use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, Vec};
use stellar_fee_abstraction::{collect_fee_and_invoke, FeeAbstractionApproval};

#[contract]
pub struct FeeForwarder;

#[contractimpl]
impl FeeForwarder {
    /// Forwards a call to a target contract while collecting a fee from the user
    /// and sending it to the relayer.
    ///
    /// Requires authorization from both the user and the relayer.
    /// The user authorizes the fee payment (up to `max_fee_amount`) and the
    /// target contract call. The relayer authorizes calling this function.
    pub fn forward(
        e: &Env,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
        user: Address,
        relayer: Address,
    ) -> Val {
        relayer.require_auth();

        collect_fee_and_invoke(
            e,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &target_contract,
            &target_fn,
            &target_args,
            &user,
            &relayer,
            FeeAbstractionApproval::Eager,
        )
    }
}
