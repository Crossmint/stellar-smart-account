#![no_std]

use soroban_sdk::prelude::*
pub mod plugin;
pub mod policy;

pub use plugin::{SmartAccountPlugin, SmartAccountPluginClient};
pub use policy::{SmartAccountPolicy, SmartAccountPolicyClient};
