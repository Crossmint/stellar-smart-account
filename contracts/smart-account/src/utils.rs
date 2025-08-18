/// Utility module for common patterns and helpers used throughout the smart account.
/// Helper macro to simplify nested Result error handling patterns.
///
/// This macro handles the common pattern where cross-contract calls return
/// nested Result structures and we want to execute some code when either
/// the outer call fails or the inner result indicates an error.
///
/// # Usage
/// ```rust
/// use crate::utils::handle_nested_result_failure;
///
/// let result = some_cross_contract_call();
/// handle_nested_result_failure!(result, {
///     // Code to execute on failure (e.g., logging, events)
///     println!("Operation failed");
/// });
/// ```
///
/// # Examples
///
/// Ignoring failures silently:
/// ```rust
/// handle_nested_result_failure!(plugin_result, {
///     // Do nothing on failure
/// });
/// ```
///
/// Emitting events on failure:
/// ```rust
/// handle_nested_result_failure!(plugin_result, {
///     env.events().publish(
///         (TOPIC_PLUGIN, VERB_FAILED),
///         PluginFailedEvent { plugin: plugin.clone() },
///     );
/// });
/// ```
#[macro_export]
macro_rules! handle_nested_result_failure {
    ($result:expr, $on_failure:block) => {
        match $result {
            Ok(inner) => {
                if inner.is_err() {
                    $on_failure
                }
            }
            Err(_) => $on_failure,
        }
    };
}

pub use handle_nested_result_failure;
