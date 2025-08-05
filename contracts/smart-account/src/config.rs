use soroban_sdk::{symbol_short, Symbol};

pub const SIGNER_TOPIC: Symbol = symbol_short!("signer");
pub const PLUGIN_TOPIC: Symbol = symbol_short!("plugin");
pub const STORAGE_TOPIC: Symbol = symbol_short!("storage");

pub const ADDED_EVENT: Symbol = symbol_short!("added");
pub const UPDATED_EVENT: Symbol = symbol_short!("updated");
pub const REVOKED_EVENT: Symbol = symbol_short!("revoked");
pub const INSTALLED_EVENT: Symbol = symbol_short!("installed");
pub const UNINSTALLED_EVENT: Symbol = symbol_short!("uninstall");
pub const CALLBACK_FAILED_EVENT: Symbol = symbol_short!("cb_failed");

pub const PLUGINS_KEY: Symbol = symbol_short!("plugins");
