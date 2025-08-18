use soroban_sdk::symbol_short;

pub const PLUGINS_KEY: soroban_sdk::Symbol = symbol_short!("plugins");
pub const ADMIN_COUNT_KEY: soroban_sdk::Symbol = symbol_short!("admin_cnt");

pub const TOPIC_SIGNER: soroban_sdk::Symbol = symbol_short!("signer");
pub const TOPIC_PLUGIN: soroban_sdk::Symbol = symbol_short!("plugin");
pub const TOPIC_POLICY: soroban_sdk::Symbol = symbol_short!("policy");

pub const VERB_ADDED: soroban_sdk::Symbol = symbol_short!("added");
pub const VERB_UPDATED: soroban_sdk::Symbol = symbol_short!("updated");
pub const VERB_REVOKED: soroban_sdk::Symbol = symbol_short!("revoked");
pub const VERB_INSTALLED: soroban_sdk::Symbol = symbol_short!("installed");
pub const VERB_UNINSTALLED: soroban_sdk::Symbol = symbol_short!("uninst");
pub const VERB_UNINSTALL_FAILED: soroban_sdk::Symbol = symbol_short!("uninsterr");
pub const VERB_AUTH_FAILED: soroban_sdk::Symbol = symbol_short!("autherr");
pub const VERB_CALLBACK_FAILED: soroban_sdk::Symbol = symbol_short!("cbfailed");
