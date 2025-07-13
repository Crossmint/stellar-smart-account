# Stellar Smart Account System

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Soroban SDK](https://img.shields.io/badge/soroban--sdk-22.0.0-blue.svg)](https://soroban.stellar.org/)
[![Test Status](https://github.com/Crossmint/stellar-smart-account/workflows/Test/badge.svg)](https://github.com/Crossmint/stellar-smart-account/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A comprehensive smart contract system for Stellar/Soroban that provides enterprise-grade account management with multi-signature support, role-based access control, and policy-based authorization. Designed for both human users and AI agents requiring sophisticated permission systems.

## 🌟 Features

- **🔐 Multi-Signature Wallet**: Advanced smart wallet with customizable authentication
- **🏭 Contract Factory**: Secure deployment system with role-based access control  
- **🎯 Role-Based Permissions**: Admin, Standard, and Restricted signer roles
- **📋 Policy System**: Time-based, contract allow/deny lists, and extensible policies
- **🤖 AI Agent Ready**: Built for both human users and automated systems
- **⚡ Soroban Native**: Leverages Stellar's smart contract platform capabilities
- **🔄 Upgradeable**: Built-in contract upgrade support with permission controls
- **📚 TypeScript Bindings**: Auto-generated JavaScript/TypeScript libraries

## 🏗️ Architecture

The system consists of two main smart contracts and supporting JavaScript libraries:

```
stellar-smart-account/
├── contracts/
│   ├── smart-wallet/          # Multi-signature wallet contract
│   ├── contract-factory/      # Secure contract deployment factory
│   ├── initializable/         # Contract initialization utilities
│   ├── storage/              # Storage management utilities
│   └── upgradeable/          # Contract upgrade utilities
├── packages/
│   ├── smart_wallet/         # TypeScript bindings for smart wallet
│   └── factory/              # TypeScript bindings for factory
└── examples/                 # Usage examples and demos
```

### Smart Wallet Contract

The core smart wallet provides:

- **Multiple Signature Schemes**: Ed25519 and Secp256r1 (WebAuthn/passkeys), extensible to others
- **Flexible Authorization**: Role-based access with policy enforcement
- **Multi-Signature Support**: Customizable authorization logic
- **Soroban Integration**: Native account interface implementation

### Contract Factory

Secure deployment system featuring:

- **Role-Based Deployment**: Only authorized deployers can create contracts
- **Deterministic Addresses**: Predictable contract addresses using salt values
- **Access Control Integration**: Built on OpenZeppelin Stellar contracts

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ with `wasm32-unknown-unknown` target
- [Stellar CLI](https://soroban.stellar.org/docs/getting-started/setup)
- Node.js 18+ (for JavaScript bindings)

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

4. **Install JavaScript dependencies** (optional):
```bash
cd packages/smart_wallet && npm install
cd ../factory && npm install
```

## 🔑 Authentication & Permissions

### Signer Roles

| Role | Capabilities | Use Cases |
|------|-------------|-----------|
| **Admin** | Full access, can upgrade contracts | System administrators, emergency access |
| **Standard** | Normal operations, cannot modify signers | Regular users, application accounts |
| **Restricted** | Policy-controlled access | Temporary access, AI agents, limited permissions |

### Policy Types

- **Time-Based**: Restrict signer validity to specific time windows
- **Contract Allow List**: Only permit interactions with specified contracts  
- **Contract Deny List**: Block interactions with specified contracts
- **Extensible**: Add custom policies for spending limits, rate limiting, etc.

### Example: Time-Restricted AI Agent

```rust
// Create an AI agent with time-limited access
let time_policy = TimeBasedPolicy {
    not_before: start_timestamp,
    not_after: end_timestamp,
};

let ai_signer = Signer::Ed25519(
    Ed25519Signer::new(ai_agent_pubkey),
    SignerRole::Restricted(vec![SignerPolicy::TimeBased(time_policy)])
);
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

The project maintains 80%+ test coverage with comprehensive integration tests.

## 🔧 Development

### Adding New Signer Types

1. Define the signer struct in `src/auth/signers/`
2. Implement the `SignatureVerifier` trait
3. Add variants to `SignerKey`, `Signer`, and `SignerProof` enums
4. Update match statements in implementation files

### Adding New Policies

1. Create policy struct in `src/auth/policy/`
2. Implement `AuthorizationCheck` and `PolicyValidator` traits
3. Add to `SignerPolicy` enum
4. Update policy validation logic

See the [Smart Wallet Architecture Documentation](contracts/smart-wallet/README.md) for detailed extension guides.

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
