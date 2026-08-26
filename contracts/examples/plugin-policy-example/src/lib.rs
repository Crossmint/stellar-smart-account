#![no_std]
use smart_account_interfaces::{PolicyError, SignerKey, SmartAccountPlugin, SmartAccountPolicy};
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractevent, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
    TryFromVal, Vec,
};

const AUTH_COUNTER_KEY: Symbol = symbol_short!("COUNTER");

const DAY_IN_LEDGERS: u32 = 17_280;
const PERSISTENT_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const PERSISTENT_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

/// Storage key for the per-source counters. Each source gets its own
/// persistent entry, so the shared instance entry does not grow with the
/// number of accounts using this plugin.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DataKey {
    /// Keyed by the account that triggered the authorization callback.
    SourceCounter(Address),
}

#[contract]
pub struct PluginPolicyContract;

#[contractevent(topics = ["AUTH"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthEvent {
    #[topic]
    pub source: Address,
    pub context_count: u32,
    pub counter: u32,
}

#[contractevent(topics = ["POL_AUTH"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAuthEvent {
    #[topic]
    pub source: Address,
    pub context_count: u32,
    pub counter: u32,
}

#[contractevent(topics = ["DENY"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferDeniedEvent {
    #[topic]
    pub source: Address,
    pub amount: i128,
    pub limit: i128,
}

/// Records one authorization callback from `source`, bumping the global
/// counter and that source's own counter. Returns the new
/// `(global, per_source)` values.
fn bump_auth_counters(env: &Env, source: &Address) -> (u32, u32) {
    let global: u32 = env.storage().instance().get(&AUTH_COUNTER_KEY).unwrap_or(0) + 1;
    env.storage().instance().set(&AUTH_COUNTER_KEY, &global);

    let source_key = DataKey::SourceCounter(source.clone());
    let per_source: u32 = env.storage().persistent().get(&source_key).unwrap_or(0) + 1;
    env.storage().persistent().set(&source_key, &per_source);
    env.storage().persistent().extend_ttl(
        &source_key,
        PERSISTENT_TTL_THRESHOLD,
        PERSISTENT_EXTEND_TO,
    );

    (global, per_source)
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
        // Increment the global counter and this source's own counter
        let (global_counter, _) = bump_auth_counters(env, &source);

        // Emit an event
        AuthEvent {
            source: source.clone(),
            context_count: contexts.len(),
            counter: global_counter,
        }
        .publish(env);
    }
}

#[contractimpl]
impl SmartAccountPolicy for PluginPolicyContract {
    fn on_add(_env: &Env, source: Address, _signer_key: SignerKey) -> Result<(), PolicyError> {
        source.require_auth();
        Ok(())
    }

    fn on_revoke(_env: &Env, source: Address, _signer_key: SignerKey) -> Result<(), PolicyError> {
        source.require_auth();
        Ok(())
    }

    fn is_authorized(
        env: &Env,
        source: Address,
        _signer_key: SignerKey,
        contexts: Vec<Context>,
    ) -> Result<(), PolicyError> {
        source.require_auth();
        // Increment the counter for policy authorization checks
        let (global_counter, _) = bump_auth_counters(env, &source);

        // Emit an event with the current counter
        PolicyAuthEvent {
            source: source.clone(),
            context_count: contexts.len(),
            counter: global_counter,
        }
        .publish(env);

        const TRANSFER_LIMIT: i128 = 100;

        // Check each context for transfers with amounts > 100
        for context in contexts.iter() {
            if let Context::Contract(contract_context) = context {
                let ContractContext { fn_name, args, .. } = contract_context;

                // Check if this is a transfer function call
                if fn_name == symbol_short!("transfer") && args.len() >= 3 {
                    if let Ok(amount) = i128::try_from_val(env, &args.get(2).unwrap()) {
                        if amount > TRANSFER_LIMIT {
                            TransferDeniedEvent {
                                source: source.clone(),
                                amount,
                                limit: TRANSFER_LIMIT,
                            }
                            .publish(env);
                            return Err(PolicyError::Unknown);
                        }
                    }
                }
            }
        }

        // If no transfer exceeds the limit, authorize the transaction
        Ok(())
    }
}

// Counter readers (for testing purposes)
#[contractimpl]
impl PluginPolicyContract {
    /// Authorization callbacks from every account since deployment.
    pub fn get_auth_counter(env: Env) -> u32 {
        env.storage().instance().get(&AUTH_COUNTER_KEY).unwrap_or(0)
    }

    /// Authorization callbacks from `source` alone. Tests running in parallel
    /// against separate accounts do not observe each other's calls here.
    pub fn get_auth_counter_for(env: Env, source: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SourceCounter(source))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        auth::ContractContext,
        testutils::{Address as _, BytesN as _},
        BytesN, IntoVal,
    };

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

        // Both counters should start at 0
        assert_eq!(client.get_auth_counter(), 0);
        assert_eq!(client.get_auth_counter_for(&source), 0);

        // Call on_auth
        client.on_auth(&source, &contexts);

        // Both counters should be incremented
        assert_eq!(client.get_auth_counter(), 1);
        assert_eq!(client.get_auth_counter_for(&source), 1);

        // Call on_auth again
        client.on_auth(&source, &contexts);

        // Both counters should be incremented again
        assert_eq!(client.get_auth_counter(), 2);
        assert_eq!(client.get_auth_counter_for(&source), 2);
    }

    #[test]
    fn test_auth_counter_is_isolated_per_source() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let first = Address::generate(&env);
        let second = Address::generate(&env);
        let contexts = Vec::new(&env);

        client.on_auth(&first, &contexts);
        client.on_auth(&second, &contexts);
        client.on_auth(&first, &contexts);

        // Each source only sees its own callbacks
        assert_eq!(client.get_auth_counter_for(&first), 2);
        assert_eq!(client.get_auth_counter_for(&second), 1);

        // The global counter still sees all of them
        assert_eq!(client.get_auth_counter(), 3);

        // A source that never authorized reads 0
        assert_eq!(client.get_auth_counter_for(&Address::generate(&env)), 0);
    }

    fn dummy_signer_key(env: &Env) -> SignerKey {
        SignerKey::Ed25519(BytesN::random(env))
    }

    #[test]
    fn test_policy_allows_small_transfers() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let token_address = Address::generate(&env);

        let transfer_context = Context::Contract(ContractContext {
            contract: token_address,
            fn_name: symbol_short!("transfer"),
            args: (Address::generate(&env), Address::generate(&env), 50i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(transfer_context);

        client.is_authorized(&source, &dummy_signer_key(&env), &contexts);

        // Policy checks bump the same pair of counters as on_auth
        assert_eq!(client.get_auth_counter(), 1);
        assert_eq!(client.get_auth_counter_for(&source), 1);
    }

    #[test]
    #[should_panic]
    fn test_policy_denies_large_transfers() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let token_address = Address::generate(&env);

        let transfer_context = Context::Contract(ContractContext {
            contract: token_address,
            fn_name: symbol_short!("transfer"),
            args: (Address::generate(&env), Address::generate(&env), 150i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(transfer_context);

        // Returns Err(PolicyError::Unknown) — the SDK's non-`try_*` client wrapper
        // turns contracterror returns into panics, so we use #[should_panic].
        client.is_authorized(&source, &dummy_signer_key(&env), &contexts);
    }

    #[test]
    fn test_policy_allows_non_transfer_operations() {
        let env = setup();
        env.mock_all_auths();
        let contract_id = env.register(PluginPolicyContract, ());
        let client = PluginPolicyContractClient::new(&env, &contract_id);

        let source = Address::generate(&env);
        let contract_address = Address::generate(&env);

        let other_context = Context::Contract(ContractContext {
            contract: contract_address,
            fn_name: symbol_short!("approve"),
            args: (Address::generate(&env), 1000i128).into_val(&env),
        });

        let mut contexts = Vec::new(&env);
        contexts.push_back(other_context);

        client.is_authorized(&source, &dummy_signer_key(&env), &contexts);
    }
}
