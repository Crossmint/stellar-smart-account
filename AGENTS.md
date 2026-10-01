# Stellar Smart Account — Agent Reference

Soroban smart contracts for a programmable Stellar account: the smart account (`contracts/smart-account`), its factory, shared interfaces, SEP-45 web auth, storage/upgrade/initialization helpers, and plugins/policies. See `README.md` for architecture and permissions.

## Best practices

At session start, run `./scripts/fetch-best-practices.sh` and read the file it names before writing or reviewing code. That file holds every rule in `Paella-Labs/best-practices`; this `AGENTS.md` adds what is specific to this repo. When reviewing PRs in this repo, check changes against both and cite the file and rule when flagging.

## Commands

Requires Rust with the `wasm32-unknown-unknown` target and the Stellar CLI.

```bash
stellar contract build   # build the contracts
cargo test               # run all tests
cargo fmt --check
```

## Testing

- Contract tests use the Soroban `Env` test utilities in each contract's `src/tests/` or `#[cfg(test)]` modules and run with `cargo test`.
- New and changed code follows `code/test.md` in the fetched best practices; existing test suites stay.
- PR evidence to link in the PR description: an explorer link or transaction signature for the devnet/testnet deployment and interaction run, made deterministic with fixed seeds/keys in the test.
