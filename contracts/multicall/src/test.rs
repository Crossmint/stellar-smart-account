extern crate std;

use soroban_sdk::testutils::{
    Address as _, AuthorizedFunction, AuthorizedInvocation, MockAuth, MockAuthInvoke,
};
use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
use soroban_sdk::{symbol_short, vec, Address, Env, Error, IntoVal, Symbol, TryFromVal, Val, Vec};

use crate::{Call, Multicall, MulticallClient};

mod counter {
    use soroban_sdk::{contract, contracterror, contractimpl, panic_with_error, symbol_short, Env};

    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub enum CounterError {
        AfterWrite = 9,
    }

    #[contract]
    pub struct Counter;

    #[contractimpl]
    impl Counter {
        pub fn increment(env: Env) -> u32 {
            let count: u32 = env
                .storage()
                .instance()
                .get(&symbol_short!("count"))
                .unwrap_or(0)
                + 1;
            env.storage()
                .instance()
                .set(&symbol_short!("count"), &count);
            count
        }

        pub fn count(env: Env) -> u32 {
            env.storage()
                .instance()
                .get(&symbol_short!("count"))
                .unwrap_or(0)
        }

        pub fn increment_then_fail(env: Env) -> u32 {
            Self::increment(env.clone());
            panic_with_error!(&env, CounterError::AfterWrite)
        }
    }
}

mod calculator {
    use soroban_sdk::{contract, contractimpl, symbol_short, vec, Address, Env, Symbol, Vec};

    #[contract]
    pub struct Calculator;

    #[contractimpl]
    impl Calculator {
        pub fn add(_env: Env, a: u32, b: u32) -> u32 {
            a + b
        }

        pub fn greet(_env: Env) -> Symbol {
            symbol_short!("hello")
        }

        pub fn noop(_env: Env) {}

        pub fn range(env: Env, to: u32) -> Vec<u32> {
            let mut out = vec![&env];
            for i in 0..to {
                out.push_back(i);
            }
            out
        }

        pub fn sum(_env: Env, values: Vec<u32>) -> u32 {
            values.iter().sum()
        }

        pub fn echo_address(_env: Env, address: Address) -> Address {
            address
        }
    }
}

mod failing {
    use soroban_sdk::{contract, contracterror, contractimpl, panic_with_error, Env};

    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub enum FailError {
        Boom = 7,
    }

    #[contract]
    pub struct Failing;

    #[contractimpl]
    impl Failing {
        pub fn fail(env: Env) -> u32 {
            panic_with_error!(&env, FailError::Boom)
        }
    }
}

mod gated {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct Gated;

    #[contractimpl]
    impl Gated {
        pub fn protected(_env: Env, who: Address) -> u32 {
            who.require_auth();
            1
        }
    }
}

mod relay {
    use soroban_sdk::{contract, contractimpl, vec, Address, Env, Symbol};

    #[contract]
    pub struct Relay;

    #[contractimpl]
    impl Relay {
        pub fn forward(env: Env, target: Address, function: Symbol) -> u32 {
            env.invoke_contract(&target, &function, vec![&env])
        }
    }
}

use calculator::Calculator;
use counter::{Counter, CounterClient};
use failing::Failing;
use gated::Gated;
use relay::Relay;

struct Harness {
    env: Env,
    multicall: Address,
    counter: Address,
    calculator: Address,
    failing: Address,
    gated: Address,
    caller: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    Harness {
        multicall: env.register(Multicall, ()),
        counter: env.register(Counter, ()),
        calculator: env.register(Calculator, ()),
        failing: env.register(Failing, ()),
        gated: env.register(Gated, ()),
        caller: Address::generate(&env),
        env,
    }
}

fn call(
    env: &Env,
    contract: &Address,
    function: &str,
    args: Vec<Val>,
    allow_failure: bool,
) -> Call {
    Call {
        contract: contract.clone(),
        function: Symbol::new(env, function),
        args,
        allow_failure,
    }
}

fn as_u32(env: &Env, value: &Val) -> u32 {
    u32::try_from_val(env, value).unwrap()
}

fn as_symbol(env: &Env, value: &Val) -> Symbol {
    Symbol::try_from_val(env, value).unwrap()
}

fn as_error(env: &Env, value: &Val) -> Error {
    Error::try_from_val(env, value).unwrap()
}

fn is_error(env: &Env, value: &Val) -> bool {
    Error::try_from_val(env, value).is_ok()
}

#[test]
fn executes_calls_in_order_with_typed_results() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.calculator,
            "add",
            vec![&h.env, 2u32.into_val(&h.env), 3u32.into_val(&h.env)],
            false,
        ),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(results.len(), 3);
    assert_eq!(as_u32(&h.env, &results.get(0).unwrap()), 5);
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
    assert_eq!(as_u32(&h.env, &results.get(2).unwrap()), 1);
}

#[test]
fn returns_void_for_unit_returning_calls() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &h.calculator, "noop", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(results.len(), 1);
    assert!(results.get(0).unwrap().is_void());
}

#[test]
fn empty_batch_returns_no_results() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let results = client.exec(&h.caller, &vec![&h.env]);

    assert_eq!(results.len(), 0);
}

#[test]
fn forwards_container_and_address_arguments() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let values: Vec<u32> = vec![&h.env, 10, 20, 30];
    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.calculator,
            "range",
            vec![&h.env, 4u32.into_val(&h.env)],
            false,
        ),
        call(
            &h.env,
            &h.calculator,
            "sum",
            vec![&h.env, values.into_val(&h.env)],
            false,
        ),
        call(
            &h.env,
            &h.calculator,
            "echo_address",
            vec![&h.env, h.caller.into_val(&h.env)],
            false,
        ),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(
        Vec::<u32>::try_from_val(&h.env, &results.get(0).unwrap()).unwrap(),
        vec![&h.env, 0, 1, 2, 3]
    );
    assert_eq!(as_u32(&h.env, &results.get(1).unwrap()), 60);
    assert_eq!(
        Address::try_from_val(&h.env, &results.get(2).unwrap()).unwrap(),
        h.caller
    );
}

#[test]
fn strict_failure_reverts_the_whole_batch() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
        call(&h.env, &h.failing, "fail", vec![&h.env], false),
    ];
    let result = client.try_exec(&h.caller, &calls);

    assert!(matches!(
        result,
        Err(Ok(error)) if error == Error::from_contract_error(7)
    ));
    assert_eq!(CounterClient::new(&h.env, &h.counter).count(), 0);
}

#[test]
fn tolerated_failure_records_error_and_continues() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
        call(&h.env, &h.failing, "fail", vec![&h.env], true),
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(results.len(), 3);
    assert_eq!(as_u32(&h.env, &results.get(0).unwrap()), 1);
    assert_eq!(
        as_error(&h.env, &results.get(1).unwrap()),
        Error::from_contract_error(7)
    );
    assert_eq!(as_u32(&h.env, &results.get(2).unwrap()), 2);
    assert_eq!(CounterClient::new(&h.env, &h.counter).count(), 2);
}

#[test]
fn tolerated_failure_rolls_back_its_own_effects_only() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.counter,
            "increment_then_fail",
            vec![&h.env],
            true,
        ),
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(
        as_error(&h.env, &results.get(0).unwrap()),
        Error::from_contract_error(9)
    );
    assert_eq!(as_u32(&h.env, &results.get(1).unwrap()), 1);
    assert_eq!(CounterClient::new(&h.env, &h.counter).count(), 1);
}

#[test]
fn requires_caller_authorization() {
    let h = setup();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let result = client.try_exec(&h.caller, &calls);

    assert!(result.is_err());
}

#[test]
fn single_authorization_covers_nested_requirements() {
    let h = setup();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.gated,
            "protected",
            vec![&h.env, h.caller.into_val(&h.env)],
            false,
        ),
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
    ];
    let results = client
        .mock_auths(&[MockAuth {
            address: &h.caller,
            invoke: &MockAuthInvoke {
                contract: &h.multicall,
                fn_name: "exec",
                args: (h.caller.clone(), calls.clone()).into_val(&h.env),
                sub_invokes: &[MockAuthInvoke {
                    contract: &h.gated,
                    fn_name: "protected",
                    args: (h.caller.clone(),).into_val(&h.env),
                    sub_invokes: &[],
                }],
            },
        }])
        .exec(&h.caller, &calls);

    assert_eq!(as_u32(&h.env, &results.get(0).unwrap()), 1);
    assert_eq!(as_u32(&h.env, &results.get(1).unwrap()), 1);
}

#[test]
fn records_one_auth_tree_for_the_batch() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.gated,
            "protected",
            vec![&h.env, h.caller.into_val(&h.env)],
            false,
        ),
    ];
    client.exec(&h.caller, &calls);

    assert_eq!(
        h.env.auths(),
        std::vec![(
            h.caller.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.multicall.clone(),
                    Symbol::new(&h.env, "exec"),
                    (h.caller.clone(), calls.clone()).into_val(&h.env),
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        h.gated.clone(),
                        Symbol::new(&h.env, "protected"),
                        (h.caller.clone(),).into_val(&h.env),
                    )),
                    sub_invocations: std::vec![],
                }],
            }
        )]
    );
}

#[test]
fn auth_failure_in_tolerated_call_does_not_block_batch() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.gated,
            "protected",
            vec![&h.env, stranger.into_val(&h.env)],
            true,
        ),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let results = client
        .mock_auths(&[MockAuth {
            address: &h.caller,
            invoke: &MockAuthInvoke {
                contract: &h.multicall,
                fn_name: "exec",
                args: (h.caller.clone(), calls.clone()).into_val(&h.env),
                sub_invokes: &[],
            },
        }])
        .exec(&h.caller, &calls);

    assert_eq!(
        as_error(&h.env, &results.get(0).unwrap()),
        Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InvalidAction)
    );
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
}

#[test]
fn unknown_function_failure_is_containable() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &h.calculator, "no_such_fn", vec![&h.env], true),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert!(is_error(&h.env, &results.get(0).unwrap()));
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
}

#[test]
fn unknown_contract_failure_is_containable() {
    let h = setup();
    h.env.mock_all_auths();
    let ghost = Address::generate(&h.env);
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(&h.env, &ghost, "greet", vec![&h.env], true),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert!(is_error(&h.env, &results.get(0).unwrap()));
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
}

#[test]
fn reentry_into_the_router_is_rejected() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let inner_calls: Vec<Call> = vec![
        &h.env,
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.multicall,
            "exec",
            vec![
                &h.env,
                h.caller.into_val(&h.env),
                inner_calls.into_val(&h.env),
            ],
            true,
        ),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert!(is_error(&h.env, &results.get(0).unwrap()));
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
}

#[test]
fn nested_contract_calls_execute_under_one_batch() {
    let h = setup();
    h.env.mock_all_auths();
    let relay = h.env.register(Relay, ());
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &relay,
            "forward",
            vec![
                &h.env,
                h.counter.into_val(&h.env),
                Symbol::new(&h.env, "increment").into_val(&h.env),
            ],
            false,
        ),
        call(&h.env, &h.counter, "increment", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert_eq!(as_u32(&h.env, &results.get(0).unwrap()), 1);
    assert_eq!(as_u32(&h.env, &results.get(1).unwrap()), 2);
    assert_eq!(CounterClient::new(&h.env, &h.counter).count(), 2);
}

#[test]
fn large_batch_executes_fully() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let mut calls = vec![&h.env];
    for _ in 0..30 {
        calls.push_back(call(&h.env, &h.counter, "increment", vec![&h.env], false));
    }
    let results = client.exec(&h.caller, &calls);

    assert_eq!(results.len(), 30);
    for i in 0..30 {
        assert_eq!(as_u32(&h.env, &results.get(i).unwrap()), i + 1);
    }
    assert_eq!(CounterClient::new(&h.env, &h.counter).count(), 30);
}

#[test]
fn wrong_argument_count_is_containable() {
    let h = setup();
    h.env.mock_all_auths();
    let client = MulticallClient::new(&h.env, &h.multicall);

    let calls = vec![
        &h.env,
        call(
            &h.env,
            &h.calculator,
            "add",
            vec![&h.env, 2u32.into_val(&h.env)],
            true,
        ),
        call(&h.env, &h.calculator, "greet", vec![&h.env], false),
    ];
    let results = client.exec(&h.caller, &calls);

    assert!(is_error(&h.env, &results.get(0).unwrap()));
    assert_eq!(
        as_symbol(&h.env, &results.get(1).unwrap()),
        symbol_short!("hello")
    );
}
