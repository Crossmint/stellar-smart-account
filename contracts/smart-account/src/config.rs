use soroban_sdk::symbol_short;

pub const PLUGINS_KEY: soroban_sdk::Symbol = symbol_short!("plugins");
pub const ADMIN_COUNT_KEY: soroban_sdk::Symbol = symbol_short!("admin_cnt");
pub const CONTRACT_VERSION_KEY: soroban_sdk::Symbol = symbol_short!("version");
pub const CURRENT_CONTRACT_VERSION: u32 = 2;

pub const DAY_IN_LEDGERS: u32 = 17_280;
pub const INSTANCE_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
pub const INSTANCE_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;
pub const PERSISTENT_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
pub const PERSISTENT_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;
