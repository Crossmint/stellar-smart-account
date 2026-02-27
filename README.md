# Stellar Smart Account

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Soroban SDK](https://img.shields.io/badge/soroban--sdk-22.0.0-blue.svg)](https://soroban.stellar.org/)
[![Test Status](https://github.com/Crossmint/stellar-smart-account/workflows/Test/badge.svg)](https://github.com/Crossmint/stellar-smart-account/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A comprehensive smart contract system for Stellar/Soroban that provides enterprise-grade account management with multi-signature support, role-based access control, and policy-based authorization. Designed for both human users and AI agents requiring sophisticated permission systems.

## 🌟 Features

- **🔐 Multi-Signature Account**: Advanced smart account with customizable authentication
- **🏭 Contract Factory**: Permissionless deployment system with deterministic addresses
- **🎯 Role-Based Permissions**: Admin and Standard signer roles with optional policies
- **📋 Policy System**: External delegation, token spending limits with reset windows and recipient allowlists, and extensible policies
- **🔌 Plugin System**: Extensible architecture with install/uninstall lifecycle and authorization hooks
- **🌐 External Delegation**: Delegate authorization decisions to external policy contracts
- **🤖 AI Agent Ready**: Built for both human users and automated systems
- **⚡ Soroban Native**: Leverages Stellar's smart contract platform capabilities
- **🔄 Upgradeable**: Built-in contract upgrade support with permission controls
- **🔀 V1→V2 Migration**: Built-in migration system for upgrading from v1 contracts

## 🏗️ Architecture

The system consists of multiple smart contracts and shared libraries:

```
stellar-smart-account/
├── contracts/
│   ├── smart-account/              # Multi-signature account contract with plugin support
│   ├── smart-account-interfaces/   # Shared types and trait definitions
│   ├── contract-factory/           # Permissionless contract deployment factory
│   ├── examples/
│   │   ├── plugin-policy-example/          # Example plugin+policy contract
│   │   └── plugin-policy-example-reverts/  # Example plugin that reverts on uninstall
│   ├── initializable/              # Contract initialization utilities
│   ├── storage/                    # Storage management utilities
│   ├── testing/                    # Shared test utilities
│   ├── upgradeable/                # Contract upgrade utilities
│   └── web-auth/                   # WebAuthn verification utilities
```

### Smart Account Contract

The core smart account provides:

- **Multiple Signature Schemes**: Ed25519, Secp256r1, WebAuthn (passkeys), and Multisig (M-of-N threshold), extensible to others
- **Flexible Authorization**: Role-based access with policy enforcement
- **Multi-Signature Support**: Customizable authorization logic
- **Plugin Architecture**: Extensible functionality through installable plugins
- **External Delegation**: Delegate authorization to external policy contracts
- **Soroban Integration**: Native account interface implementation

### Contract Factory

Permissionless deployment system featuring:

- **Open Deployment**: Anyone can deploy smart account contracts
- **Deterministic Addresses**: Predictable contract addresses using salt values
- **Idempotent Deploys**: Safe re-deployment attempts return existing addresses

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ with `wasm32-unknown-unknown` target
- [Stellar CLI](https://soroban.stellar.org/docs/getting-started/setup)

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Crossmint/stellar-smart-account.git
cd stellar-smart-account
```

2. **Build the contracts**:
```bash
stellar contract build
```

3. **Run tests**:
```bash
cargo test
```

## 🔑 Authentication & Permissions

### Signer Roles

| Role | Capabilities | Use Cases |
|------|-------------|-----------|
| **Admin** | Full access, can upgrade contracts | System administrators, emergency access |
| **Standard** | Normal operations, cannot modify signers, optional policy restrictions | Regular users, application accounts, AI agents with policies |

### Policy Types

- **External Delegation**: Delegate authorization decisions to external policy contracts
- **Token Transfer Policy**: Restrict signers to specific token transfers with cumulative spending limits, reset windows, recipient allowlists, and per-policy expiration
- **Extensible**: Add custom policies by implementing the `AuthorizationCheck` and `PolicyCallback` traits

### Signer Expiration

Standard signers can have an expiration timestamp. Once the ledger timestamp exceeds the expiration, the signer is rejected. A value of `0` means no expiration.

### Example: Expiring AI Agent Signer

```rust
// Create an AI agent with time-limited access using signer expiration
let ai_signer = Signer::Ed25519(
    Ed25519Signer::new(ai_agent_pubkey),
    SignerRole::Standard(None, end_timestamp) // expires at end_timestamp, 0 = no expiration
);
```

### Example: External Policy Delegation

```rust
// Delegate authorization to an external policy contract
let external_policy = ExternalPolicy {
    policy_address: deny_list_contract_address,
};

let restricted_signer = Signer::Ed25519(
    Ed25519Signer::new(signer_pubkey),
    SignerRole::Standard(
        Some(vec![SignerPolicy::ExternalValidatorPolicy(external_policy)]),
        0, // 0 = no expiration
    )
);
```

### Example: Plugin Installation

```rust
// Initialize smart account with plugins
SmartAccount::__constructor(
    env,
    vec![admin_signer],
    vec![analytics_plugin_address, logging_plugin_address]
);

// Install additional plugins after deployment
SmartAccount::install_plugin(&env, new_plugin_address)?;
```

## 🧪 Testing

Run the full test suite:

```bash
# Run all tests
cargo test

# Run with coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## 💾 Soroban Storage Strategy and Costs

For optimal performance and cost on Soroban, this project uses storage types deliberately:
- Persistent storage: durable, TTL-based entries with rent; best for long-lived, potentially larger datasets
- Instance storage: bundled with the contract entry, automatically loaded each call; best for small data needed on most calls
- Temporary storage: short TTL and cheaper rent; not used here for critical state

Applied to the Smart Account:
- Signers (SignerKey -> Signer): Persistent
- Admin count (ADMIN_COUNT_KEY): Persistent
- Plugins registry (PLUGINS_KEY): Instance (invoked on every __check_auth)
- Migration flag (MIGRATING): Instance

Why this mapping:
- Plugins are accessed on every call in __check_auth, so keeping the plugin registry in Instance storage avoids separate persistent reads on each invocation.
- Signers and admin count are long-lived and can grow; storing them in Persistent avoids growing the contract instance entry and respects durability expectations.

Notes:
- Instance storage is limited by the ledger entry size limit (approximately 128 KB for the contract entry), so only small, frequently accessed data should be kept there.
- Persistent entries accrue rent over time and can be restored after archival if TTL expires by paying a fee.

Potential future optimizations (not implemented here):
- Skip plugin callbacks when auth contexts are clearly unrelated
- Maintain a fast “has_plugins” indicator to early-exit
- Track a subset of “auth-hook” plugins to invoke only those on __check_auth

The project maintains 80%+ test coverage with comprehensive integration tests.

## 🔧 Development

### Adding New Signer Types

1. Define the signer struct in `contracts/smart-account-interfaces/src/auth/types.rs`
2. Implement the `SignatureVerifier` trait in `contracts/smart-account/src/auth/signers/`
3. Add variants to `SignerKey` and `Signer` enums in the interfaces crate, and `SignerProof` in `contracts/smart-account/src/auth/proof.rs`
4. Add a `From<NewSigner> for SignerKey` implementation
5. Update match statements in `contracts/smart-account/src/auth/signer.rs` and `contracts/smart-account/src/auth/core/authorizer.rs`

### Adding New Policies

1. Create the policy struct in `contracts/smart-account-interfaces/src/auth/types.rs`
2. Implement `AuthorizationCheck` and `PolicyCallback` traits in `contracts/smart-account/src/auth/policy/`
   - `AuthorizationCheck::is_authorized(&self, env, signer_key, contexts) -> bool`
   - `PolicyCallback::on_add(&self, env, signer_key) -> Result<(), SmartAccountError>`
   - `PolicyCallback::on_revoke(&self, env, signer_key) -> Result<(), SmartAccountError>`
3. Add a variant to the `SignerPolicy` enum in the interfaces crate
4. Update match arms in `contracts/smart-account/src/auth/permissions.rs`

See the [Smart Account Architecture Documentation](contracts/smart-account/README.md) for detailed extension guides.

## 🌐 Network Support

The contracts are designed for deployment on:

- **Stellar Testnet**: For development and testing
- **Stellar Futurenet**: For experimental features
- **Stellar Mainnet**: For production deployments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure tests pass: `cargo test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

<img src="https://www.crossmint.com/assets/crossmint/logo.png" alt="Crossmint Logo" width="120" />

### Built with ❤️ by **Crossmint**

*The enterprise infrastructure powering the next generation of cross-chain applications*

**[🚀 Explore Crossmint Wallets](https://docs.crossmint.com/wallets/overview)** | **[🌐 Visit Crossmint.com](https://crossmint.com/)**

</div>
