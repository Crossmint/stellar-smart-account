#![no_std]
use smart_account_interfaces::{SmartAccountPlugin, SmartAccountPolicy};
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, TryFromVal, Vec,
};

const AUTH_COUNTER_KEY: Symbol = symbol_short!("COUNTER");

#[contract]
pub struct PluginPolicyContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthEvent {
    pub source: Address,
    pub context_count: u32,
    pub counter: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferDeniedEvent {
    pub source: Address,
    pub amount: i128,
    pub limit: i128,
}

#[contractimpl]
impl SmartAccountPlugin for PluginPolicyContract {
    fn on_install(_env: &Env, source: Address) {
        source.require_auth();
    }

    fn on_uninstall(_env: &Env, source: Address) {
        source.require_auth();
    }

    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>) {
        source.require_auth();
        // Increment the internal counter
        let current_counter: u32 = env.storage().instance().get(&AUTH_COUNTER_KEY).unwrap_or(0);

        let new_counter = current_counter + 1;
        env.storage()
            .instance()
            .set(&AUTH_COUNTER_KEY, &new_counter);

        // Emit an event
        env.events().publish(
            (symbol_short!("AUTH"), &source),
            AuthEvent {
                source: source.clone(),
                context_count: contexts.len(),
                counter: new_counter,
            },
        );
    }
}

#[contractimpl]
impl SmartAccountPolicy for PluginPolicyContract {
    fn on_add(_env: &Env, source: Address) {
        source.require_auth();
    }

    fn on_revoke(_env: &Env, source: Address) {
        source.require_auth();
    }

    fn is_authorized(env: &Env, source: Address, contexts: Vec<Context>) -> bool {
        source.require_auth();
        // Increment the counter for policy authorization checks
        let current_counter: u32 = env.storage().instance().get(&AUTH_COUNTER_KEY).unwrap_or(0);
        let new_counter = current_counter + 1;
        env.storage()
            .instance()
            .set(&AUTH_COUNTER_KEY, &new_counter);

        // Emit an event with the current counter
        env.events().publish(
            (symbol_short!("POL_AUTH"), &source),
            AuthEvent {
                source: source.clone(),
                context_count: contexts.len(),
                counter: new_counter,
            },
        );

        const TRANSFER_LIMIT: i128 = 100;

        // Check each context for transfers with amounts > 100
        for context in contexts.iter() {
            if let Context::Contract(contract_context) = context {
                let ContractContext { fn_name, args, .. } = contract_context;

                // Check if this is a transfer function call
                if fn_name == symbol_short!("transfer") && args.len() >= 3 {
                    if let Ok(amount) = i128::try_from_val(env, &args.get(2).unwrap()) {
                        if amount > TRANSFER_LIMIT {
                            env.events().publish(
                                (symbol_short!("DENY"), &source),
                                TransferDeniedEvent {
                                    source: source.clone(),
                                    amount,
                                    limit: TRANSFER_LIMIT,
                                },
                            );
                            return false;
                        }
                    }
                }
            }
        }

        // If no transfer exceeds the limit, authorize the transaction
        true
    }
}

// Helper function to get the current counter (for testing purposes)
#[contractimpl]
impl PluginPolicyContract {
    pub fn get_auth_counter(env: Env) -> u32 {
        env.storage().instance().get(&AUTH_COUNTER_KEY).unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{auth::ContractContext, testutils::Address as _, IntoVal};

    fn setup() -> Env {
        Env::default()
    }

    #[test]
    fn test_on_auth_increments_counter() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let contexts = Vec::new(&env);

        // Initial counter should be 0
        assert_eq!(client.get_auth_counter(), 0);

        // Call on_auth
        client.on_auth(&source, &contexts);

        // Counter should be incremented
        assert_eq!(client.get_auth_counter(), 1);

        // Call on_auth again
        client.on_auth(&source, &contexts);

        // Counter should be incremented again
        assert_eq!(client.get_auth_counter(), 2);
    }

    #[test]
    fn test_policy_allows_small_transfers() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let token_address = Address::generate(&env);

        // Create a transfer context with amount 50 (less than 100)
        let transfer_context = Context::Contract(ContractContext {
            contract: token_address,
            fn_name: symbol_short!("transfer"),
            args: (Address::generate(&env), Address::generate(&env), 50i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(transfer_context);

        // Should be authorized (amount <= 100)
        assert!(client.is_authorized(&source, &contexts));
    }

    #[test]
    fn test_policy_denies_large_transfers() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let token_address = Address::generate(&env);

        // Create a transfer context with amount 150 (greater than 100)
        let transfer_context = Context::Contract(ContractContext {
            contract: token_address,
            fn_name: symbol_short!("transfer"),
            args: (Address::generate(&env), Address::generate(&env), 150i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(transfer_context);

        // Should NOT be authorized (amount > 100)
        assert!(!client.is_authorized(&source, &contexts));
    }

    #[test]
    fn test_policy_allows_non_transfer_operations() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let contract_address = Address::generate(&env);

        // Create a non-transfer context
        let other_context = Context::Contract(ContractContext {
            contract: contract_address,
            fn_name: symbol_short!("approve"),
            args: (Address::generate(&env), 1000i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(other_context);

        // Should be authorized (not a transfer)
        assert!(client.is_authorized(&source, &contexts));
    }
}
