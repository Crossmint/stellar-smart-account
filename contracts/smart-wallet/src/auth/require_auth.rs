#[macro_export]
macro_rules! require_auth {
    ($env:expr) => {
        if Self::is_initialized($env) {
            $env.current_contract_address().require_auth();
        }
    };
}
