use crate::config::{TOPIC_PLUGIN, VERB_AUTH_FAILED};
use crate::error::Error;
use crate::events::PluginAuthFailedEvent;
use crate::plugin::SmartAccountPluginClient;
use soroban_sdk::{auth::Context, contracttype, Address, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Plugin {
    BlockingPlugin(Address),
    NonBlockingPlugin(Address),
}

impl Plugin {
    pub fn address(&self) -> Address {
        match self {
            Plugin::BlockingPlugin(address) => address.clone(),
            Plugin::NonBlockingPlugin(address) => address.clone(),
        }
    }
    pub fn execute(&self, env: &Env, auth_contexts: &Vec<Context>) -> Result<(), Error> {
        let address = self.address();
        let on_auth_result = SmartAccountPluginClient::new(&env, &address)
            .try_on_auth(&env.current_contract_address(), &auth_contexts);

        match on_auth_result {
            Ok(inner) => {
                if inner.is_err() {
                    env.events().publish(
                        (TOPIC_PLUGIN, address, VERB_AUTH_FAILED),
                        PluginAuthFailedEvent {
                            plugin: self.clone(),
                            error: soroban_sdk::String::from_str(&env, "Plugin execution failed"),
                        },
                    );
                    return match self {
                        Plugin::BlockingPlugin(_) => Err(Error::PluginExecutionFailed),
                        Plugin::NonBlockingPlugin(_) => Ok(()),
                    };
                }
                Ok(())
            }
            Err(e) => {
                env.events().publish(
                    (TOPIC_PLUGIN, address, VERB_AUTH_FAILED),
                    PluginAuthFailedEvent {
                        plugin: self.clone(),
                        error: soroban_sdk::String::from_str(&env, "Plugin execution failed"),
                    },
                );
                match self {
                    Plugin::BlockingPlugin(_) => Err(Error::PluginExecutionFailed),
                    Plugin::NonBlockingPlugin(_) => Ok(()),
                }
            }
        }
    }
}
