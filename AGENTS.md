# Stellar Smart Account — Agent Reference

Soroban smart contracts for a programmable Stellar account: the smart account (`contracts/smart-account`), its factory, shared interfaces, SEP-45 web auth, storage/upgrade/initialization helpers, and plugins/policies. See `README.md` for architecture and permissions.

## Best Practices

Before each step of a task, run `"$BP" list`: it prints every topic of the Paella best practices and when it applies. Read the ones that apply with `"$BP" read <topic>...` and follow them. Following a topic means following the topics above it too: `read` prints the root `README.md` and the `README.md` of every directory above the file, and those apply as well.

    BP="${PAELLA_BEST_PRACTICES_DIR:-$HOME/.cache/paella-best-practices}/bin/best-practices.sh"
    [ -x "$BP" ] || { mkdir -p "$(dirname "$BP")" && { gh api -H 'Accept: application/vnd.github.raw' repos/Paella-Labs/best-practices/contents/bin/best-practices.sh > "$BP.$$" 2>/dev/null || { T=$(mktemp -d) && GIT_TERMINAL_PROMPT=0 git clone -q --depth=1 https://github.com/Paella-Labs/best-practices.git "$T" && cp "$T/bin/best-practices.sh" "$BP.$$"; s=$?; rm -rf "$T"; [ "$s" = 0 ]; }; } && [ -s "$BP.$$" ] && bash -n "$BP.$$" && chmod +x "$BP.$$" && mv -f "$BP.$$" "$BP" || rm -f "$BP.$$"; }
    "$BP" list

## Commands

Requires Rust with the `wasm32-unknown-unknown` target and the Stellar CLI.

```bash
stellar contract build   # build the contracts
cargo test               # run all tests
cargo fmt --check
```

## Testing

- Contract tests use the Soroban `Env` test utilities in each contract's `src/tests/` or `#[cfg(test)]` modules and run with `cargo test`.
- New and changed code follows the `code/test` best practices.
