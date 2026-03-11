# Stellar Smart Account — V2 Changes for Security Review

## Overview

This document describes all changes introduced to the Stellar Smart Account since the **v1.0.0** release, which was the subject of the initial security review (Halborn, October 2025). These changes collectively form the **v2** release.

The v2 release adds four major features — **spending limits**, **signer expiration**, **v1→v2 migration**, and **permission key conflict prevention** — as well as three new signer types (**WebAuthn**, **Multisig M-of-N**, and **raw Secp256r1**), a **permissionless contract factory**, and several infrastructure improvements.

**Commit range:** `v1.0.0` (0f50d39) → `HEAD` on `main` (85d8ba7)
**PRs included:** #84 through #100
**Diff stats:** 81 files changed, ~6,400 insertions, ~6,000 deletions

---

## Table of Contents

1. [Spending Limits — TokenTransferPolicy (PR #96)](#1-spending-limits--tokentransferpolicy-pr-96)
2. [Signer Expiration (PR #97)](#2-signer-expiration-pr-97)
3. [V1 → V2 Migration (PR #98)](#3-v1--v2-migration-pr-98)
4. [Permission Key Conflict Prevention (PR #99)](#4-permission-key-conflict-prevention-pr-99)
5. [WebAuthn / Passkey Signer (PR #88)](#5-webauthn--passkey-signer-pr-88)
6. [Multisig M-of-N Threshold Signer (PR #91)](#6-multisig-m-of-n-threshold-signer-pr-91)
7. [Raw Secp256r1 Signer (PR #93)](#7-raw-secp256r1-signer-pr-93)
8. [Permissionless Contract Factory (PR #94)](#8-permissionless-contract-factory-pr-94)
9. [Wallet Address Initialization Locking (PR #89)](#9-wallet-address-initialization-locking-pr-89)
10. [Upgradeable Contract Enhancements](#10-upgradeable-contract-enhancements)
11. [Interface Crate Restructuring (PRs #84, #85)](#11-interface-crate-restructuring-prs-84-85)
12. [Other Changes (PRs #86, #87, #90, #100)](#12-other-changes-prs-86-87-90-100)
13. [Removed Features](#13-removed-features)
14. [Type System Evolution — V1 vs V2](#14-type-system-evolution--v1-vs-v2)
15. [New Error Codes](#15-new-error-codes)
16. [Test Coverage](#16-test-coverage)
17. [Key Files for Auditor Review](#17-key-files-for-auditor-review)

---

## 1. Spending Limits — TokenTransferPolicy (PR #96)

### Description

A new built-in policy type that restricts Standard signers to only calling `transfer` on a specific SAC token contract, with cumulative spending limits. Designed for AI agent control and managed spending accounts.

### Key Types

```rust
// contracts/smart-account-interfaces/src/auth/types.rs

pub struct TokenTransferPolicy {
    pub policy_id: BytesN<32>,           // Unique ID scoping the spending tracker
    pub token: Address,                   // SAC token contract this signer may call
    pub limit: i128,                      // Max cumulative amount per window
    pub reset_window_secs: u64,           // Window duration (0 = lifetime limit)
    pub allowed_recipients: Vec<Address>, // Recipient allowlist (empty = any)
    pub expiration: u64,                  // Policy expiration timestamp (0 = none)
}

pub struct SpendingTracker {
    pub spent: i128,
    pub window_start: u64,
}

pub enum SpendTrackerKey {
    TokenSpend(BytesN<32>, SignerKey),   // Keyed by (policy_id, signer_key)
}
```

### Authorization Logic

The implementation in `contracts/smart-account/src/auth/policy/token_transfer.rs` performs these checks in order:

1. **Policy expiration**: If `expiration > 0` and `now > expiration`, deny.
2. **Context validation**: ALL auth contexts must be `transfer` calls on `self.token` with exactly 3 arguments.
3. **Recipient validation**: If `allowed_recipients` is non-empty, the `to` argument must be in the list.
4. **Amount extraction**: Amount (`args[2]`) must be non-negative. Amounts from multiple contexts are summed.
5. **Window reset**: If `reset_window_secs > 0` and the window has elapsed, reset `spent` to 0.
6. **Cumulative limit**: `tracker.spent + total_amount` must not exceed `limit`.
7. **Tracker persistence**: Updated `SpendingTracker` is written to persistent storage.

### Policy Lifecycle Callbacks

- **`on_add`**: Validates `limit > 0`, validates expiration is in the future (if set), initializes the `SpendingTracker` in persistent storage.
- **`on_revoke`**: Cleans up the `SpendingTracker` entry from persistent storage.

### Storage

- `SpendTrackerKey::TokenSpend(policy_id, signer_key)` → `SpendingTracker` in persistent storage.

### Security Focus Areas

- Overflow handling: uses `checked_add` with `unwrap_or(i128::MAX)`.
- Window reset logic: uses `saturating_sub` for timestamp arithmetic.
- Spending tracker is updated during authorization (not post-auth) — side effect within `is_authorized`.
- Non-contract contexts (e.g., `Context::CreateContractHostFn`) are rejected.
- Multiple `transfer` contexts within a single auth entry are cumulative.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account-interfaces/src/auth/types.rs` | Type definitions |
| `contracts/smart-account/src/auth/policy/token_transfer.rs` | Implementation |
| `contracts/smart-account/src/auth/permissions.rs` | Policy dispatch |
| `contracts/smart-account/src/tests/token_transfer_policy_test.rs` | Tests (~700 lines) |

---

## 2. Signer Expiration (PR #97)

### Description

Standard signers can now have an expiration timestamp. Once the ledger timestamp exceeds the expiration, the signer is rejected. A value of `0` means no expiration. Admin signers always return `0` (never expire).

### Type Change

```rust
// V1:
pub enum SignerRole {
    Admin,
    Standard(Vec<SignerPolicy>),
}

// V2:
pub enum SignerRole {
    Admin,
    Standard(Option<Vec<SignerPolicy>>, u64),  // (policies, expiration)
}
```

### Expiration Check (3-Layer Defense-in-Depth)

**Layer 1 — Authorizer (early rejection, before signature verification):**
```rust
// contracts/smart-account/src/auth/core/authorizer.rs:41-44
if signer.is_expired(env) {
    return Err(Error::SignerExpired);
}
```

**Layer 2 — Permission system (defense-in-depth):**
```rust
// contracts/smart-account/src/auth/permissions.rs:68-71
SignerRole::Standard(policies, expiration) => {
    if *expiration > 0 && env.ledger().timestamp() > *expiration {
        return false;
    }
    // ...
}
```

**Layer 3 — Signer creation/update validation:**
```rust
// contracts/smart-account/src/account.rs
fn validate_signer_expiration(env, signer) -> Result<(), SmartAccountError> {
    // Rejects signers whose expiration is not strictly in the future
    if expiration > 0 && expiration <= env.ledger().timestamp() {
        return Err(SmartAccountError::SignerExpired);
    }
}
```

### Expiration Semantics

- `is_expired` returns `true` when `exp > 0 && ledger_timestamp > exp`. This means the signer is **valid at the exact expiration timestamp** and **invalid after it**.
- Layer 1 runs before the expensive signature verification (gas optimization).
- Expired signers are **not automatically removed** from storage — they remain retrievable via `get_signer()`, and an admin can revoke them.

### Security Focus Areas

- Boundary condition: `timestamp > expiration` (not `>=`).
- Admin signers always return `expiration = 0` (enforced in `Signer::expiration()`).
- Expiration checked before signature verification (prevents wasted gas on expired signers).

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account-interfaces/src/auth/types.rs` | `SignerRole`, `Signer::expiration()`, `Signer::is_expired()` |
| `contracts/smart-account/src/auth/core/authorizer.rs` | Early expiration rejection |
| `contracts/smart-account/src/auth/permissions.rs` | Defense-in-depth check |
| `contracts/smart-account/src/account.rs` | `validate_signer_expiration()` |
| `contracts/smart-account/src/tests/expiring_signer_test.rs` | Tests (~428 lines) |

---

## 3. V1 → V2 Migration (PR #98)

### Description

A migration system that allows existing v1.0.0 smart accounts to upgrade to v2 without losing signer data. The migration handles three breaking changes between v1 and v2 XDR layouts.

### Breaking Changes Handled

1. **Secp256r1 → Webauthn re-keying**: V1 used `Secp256r1` for what was effectively a WebAuthn signer. V2 introduces a dedicated `Webauthn` signer type. Storage key changes from `SignerKey::Secp256r1(key_id: Bytes)` to `SignerKey::Webauthn(key_id: Bytes)`.

2. **TimeWindowPolicy removal**: The `TimeWindowPolicy` variant is removed from the `SignerPolicy` enum in v2. During migration, any `TimeWindowPolicy` is silently dropped.

3. **Standard signer XDR layout change**: The `SignerRole::Standard` variant changed from `Standard(Vec<SignerPolicy>)` to `Standard(Option<Vec<SignerPolicy>>, u64)` — an entirely different binary layout requiring full re-serialization.

### Migration Data

```rust
// contracts/smart-account/src/migration/v1_to_v2.rs

pub struct V1ToV2MigrationData {
    pub signers_to_migrate: Vec<V1SignerKey>,
}
```

The caller must provide the explicit list of v1 signer keys that need migration. This is a design choice — the contract does not scan storage.

### Migration Process

For each signer key in the migration data:
1. Read the old entry using V1-compatible types.
2. Delete the old storage entry.
3. Convert key and value to V2 types.
4. Write the new entry.

### Version Dispatch

```rust
// contracts/smart-account/src/migration/mod.rs

pub fn run_migration(env, data) {
    let version = get_contract_version(env);  // defaults to 1 for legacy contracts
    match (version, data) {
        (1, MigrationData::V1ToV2(v1_data)) => migrate_v1_to_v2(env, v1_data),
        _ => panic_with_error!(env, Error::MigrationVersionMismatch),
    }
    set_contract_version(env, CURRENT_CONTRACT_VERSION);  // = 2
}
```

### Conversion Rules

| V1 Type | V2 Type | Notes |
|---------|---------|-------|
| `SignerKey::Secp256r1(key_id: Bytes)` | `SignerKey::Webauthn(key_id: Bytes)` | Key field changed semantics |
| `SignerKey::Ed25519(pk)` | `SignerKey::Ed25519(pk)` | Unchanged |
| `Signer::Secp256r1(signer, role)` | `Signer::Webauthn(WebauthnSigner, role)` | New struct type |
| `SignerRole::Standard(Vec<Policy>)` | `SignerRole::Standard(Option<Vec<Policy>>, 0)` | Layout + wrapping change |
| `SignerPolicy::TimeWindowPolicy(_)` | *(dropped)* | Removed variant |
| `SignerPolicy::ExternalValidatorPolicy(ext)` | `SignerPolicy::ExternalValidatorPolicy(ext)` | Preserved |

All migrated Standard signers receive `expiration = 0` (no expiration).

### V1 Type Definitions

Self-contained type definitions for V1 XDR compatibility are in `contracts/smart-account/src/migration/v1_types.rs`. These types are intentionally decoupled from current types to avoid breakage.

### Two-Phase Upgrade Flow

1. **Phase 1**: Call `upgrade(new_wasm_hash)` — sets `MIGRATING = true` in instance storage, swaps WASM.
2. **Phase 2**: Call `migrate(MigrationData::V1ToV2(data))` — runs data migration, sets `MIGRATING = false`, bumps `CONTRACT_VERSION` to 2.

Both phases require admin authorization. The `MIGRATING` flag prevents calling `migrate` without a preceding `upgrade`.

### Security Focus Areas

- Migration is **not atomic across signers** — if it fails mid-way, some signers will have been migrated while others haven't. There is no rollback mechanism.
- The caller must provide the correct list of signer keys — incorrect or missing keys will result in unmigrated entries.
- `TimeWindowPolicy` is silently dropped (not an error).
- `MIGRATING` flag prevents migration without a preceding upgrade call.
- Version dispatch prevents running the wrong migration.
- V1 type definitions must exactly match the on-chain XDR layout of v1 contracts.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account/src/migration/mod.rs` | Version dispatch, `MigrationData` enum |
| `contracts/smart-account/src/migration/v1_to_v2.rs` | Migration logic, `V1ToV2MigrationData` |
| `contracts/smart-account/src/migration/v1_types.rs` | V1-compatible type definitions |
| `contracts/upgradeable/src/lib.rs` | Two-phase upgrade framework |
| `contracts/smart-account/src/tests/upgrade_test.rs` | Tests (~1,050 lines) |
| `contracts/smart-account/testdata/smart_account_v1.wasm` | V1 WASM for integration tests |
| `contracts/smart-account/testdata/smart_account_v2.wasm` | V2 WASM for integration tests |
| `scripts/upgrade-wallet/src/main.rs` | CLI migration script (~816 lines) |

---

## 4. Permission Key Conflict Prevention (PR #99)

### Description

Fixed a storage key collision vulnerability in the spending tracker. Previously, `SpendTrackerKey` was scoped only by `policy_id`. If two different signers shared the same policy, they would share the same spending tracker, causing cross-contamination of spending data.

### Change

```rust
// Before (vulnerable):
pub enum SpendTrackerKey {
    TokenSpend(BytesN<32>),           // policy_id only
}

// After (fixed):
pub enum SpendTrackerKey {
    TokenSpend(BytesN<32>, SignerKey), // (policy_id, signer_key)
}
```

### Trait Signature Updates

The `AuthorizationCheck` and `PolicyCallback` traits now require a `signer_key` parameter:

```rust
pub trait AuthorizationCheck {
    fn is_authorized(&self, env: &Env, signer_key: &SignerKey, contexts: &Vec<Context>) -> bool;
}

pub trait PolicyCallback {
    fn on_add(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError>;
    fn on_revoke(&self, env: &Env, signer_key: &SignerKey) -> Result<(), SmartAccountError>;
}
```

### Impact

- Each signer now has isolated spending tracking even when sharing the same policy configuration.
- The `signer_key` is derived from the `Signer` in the authorizer and passed through the entire authorization chain.
- Policy lifecycle callbacks (`on_add`, `on_revoke`) also use the scoped key for tracker initialization and cleanup.

### Security Focus Areas

- Ensures no cross-signer interference through shared policy instances.
- Gas cost increase due to larger storage keys (now includes `SignerKey`).

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account-interfaces/src/auth/types.rs` | `SpendTrackerKey` definition |
| `contracts/smart-account/src/auth/permissions.rs` | Trait signatures |
| `contracts/smart-account/src/auth/policy/token_transfer.rs` | Scoped tracker access |
| `contracts/smart-account/src/auth/policy/external.rs` | Updated trait implementation |
| `contracts/smart-account/src/auth/core/authorizer.rs` | `SignerKey` derivation |
| `contracts/smart-account/src/account.rs` | Policy lifecycle plumbing |

---

## 5. WebAuthn / Passkey Signer (PR #88)

### Description

Adds support for WebAuthn/Passkey-based authentication. This is a new signer type in the smart account that enables biometric and security key authentication.

### Signer Type

```rust
pub struct WebauthnSigner {
    pub key_id: Bytes,
    pub public_key: BytesN<65>,  // Secp256r1 public key
}

pub enum SignerKey {
    // ...
    Webauthn(Bytes),  // Keyed by key_id
}

pub enum SignerProof {
    // ...
    Webauthn(WebauthnSignature),
}

pub struct WebauthnSignature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}
```

### Signature Verification Flow

In `contracts/smart-account/src/auth/signers/webauthn.rs`:

1. Concatenate `authenticator_data` with SHA-256 of `client_data_json`.
2. Verify secp256r1 signature over SHA-256 of the concatenated data.
3. Parse `client_data_json` (capped at 1024 bytes) as JSON.
4. Verify the `challenge` field matches the Base64URL-encoded `signature_payload`.

### Security Focus Areas

- `client_data_json` is capped at 1024 bytes to prevent excessive memory allocation.
- Challenge comparison uses constant-time byte comparison via Rust's `!=` on byte slices.
- Signature verification uses Soroban's native `secp256r1_verify` (panics on invalid signature).
- JSON parsing of `client_data_json` — potential for malformed input.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account/src/auth/signers/webauthn.rs` | Signature verification |
| `contracts/smart-account/src/auth/proof.rs` | `WebauthnSignature` type |
| `contracts/smart-account-interfaces/src/auth/types.rs` | `WebauthnSigner`, `SignerKey::Webauthn` |
| `contracts/smart-account/src/tests/webauthn_signer_test.rs` | Tests (~94 lines) |

---

## 6. Multisig M-of-N Threshold Signer (PR #91)

### Description

A new signer type that requires M-of-N member signatures to meet a configurable threshold. Members can use any supported signature scheme (Ed25519, Secp256r1, WebAuthn).

### Types

```rust
pub struct MultisigSigner {
    pub id: BytesN<32>,                   // Unique identifier
    pub members: Vec<MultisigMember>,
    pub threshold: u32,
}

pub enum MultisigMember {
    Ed25519(Ed25519Signer),
    Secp256r1(Secp256r1Signer),
    Webauthn(WebauthnSigner),
}

pub enum SignerKey {
    // ...
    Multisig(BytesN<32>),  // Keyed by id
}
```

### Verification Logic

In `contracts/smart-account/src/auth/signers/multisig.rs`:

1. Expects a `SignerProof::Multisig(member_proofs)` proof containing a map of `(SignerKey, SignerProof)` pairs.
2. For each proof, finds the matching member by `SignerKey` and delegates to the member's `verify()`.
3. Counts successfully verified members; authorization succeeds if `verified_count >= threshold`.

### Security Focus Areas

- Members are searched by linear scan over the `members` Vec for each proof — O(N*M) where N = members, M = provided proofs.
- Duplicate member detection happens at signer creation time (`account.rs`) — members are converted to `SignerKey` and checked for uniqueness.
- A multisig signer carries its own role (Admin or Standard with policies), which applies to the multisig as a unit.
- Member keys must be exclusive to the multisig configuration (validated on creation).
- `threshold` validation: must be > 0 and <= number of members.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account/src/auth/signers/multisig.rs` | Verification logic |
| `contracts/smart-account-interfaces/src/auth/types.rs` | `MultisigSigner`, `MultisigMember` |
| `contracts/smart-account/src/auth/proof.rs` | `SignerProof::Multisig` |
| `contracts/smart-account/src/tests/multisig_test.rs` | Tests (~394 lines) |

---

## 7. Raw Secp256r1 Signer (PR #93)

### Description

A dedicated signer type for raw NIST P-256 (secp256r1) signatures, separate from the WebAuthn signer. Intended for use with Hardware Security Modules (HSMs) and systems that produce raw ECDSA signatures without the WebAuthn envelope.

### Types

```rust
pub struct Secp256r1Signer {
    pub public_key: BytesN<65>,  // Uncompressed public key
}

pub enum SignerKey {
    // ...
    Secp256r1(BytesN<65>),  // Keyed by public_key (not key_id as in v1)
}
```

### Verification

In `contracts/smart-account/src/auth/signers/secp256r1.rs`:

- Delegates to Soroban's native `secp256r1_verify(public_key, signature_payload, signature)`.
- The `signature_payload` from `__check_auth` is guaranteed to be a SHA-256 hash, so no additional hashing is performed.

Note: In v1, `Secp256r1` was used as a WebAuthn signer (with `key_id`). In v2, `Secp256r1` is a separate raw signature type keyed by `public_key` (`BytesN<65>`), and WebAuthn is its own variant keyed by `key_id` (`Bytes`).

### Security Focus Areas

- Relies entirely on Soroban's native `secp256r1_verify` (panics on failure).
- `SignerKey::Secp256r1` changed from `Bytes` (key_id) in v1 to `BytesN<65>` (public_key) in v2 — a storage key semantic change.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account/src/auth/signers/secp256r1.rs` | Verification logic |
| `contracts/smart-account-interfaces/src/auth/types.rs` | `Secp256r1Signer` |
| `contracts/smart-account/src/tests/secp256r1_signer_test.rs` | Tests (~255 lines, refactored) |

---

## 8. Permissionless Contract Factory (PR #94)

### Description

The contract factory was refactored from a permissioned model to a fully permissionless deployment system. Anyone can deploy smart account contracts. Removed access control and admin requirements.

### Interface

```rust
// contracts/contract-factory/src/lib.rs

impl ContractFactory {
    /// Deploy a new contract
    pub fn deploy(env, deployment_args: ContractDeploymentArgs) -> Address;

    /// Deploy or return existing (idempotent)
    pub fn deploy_idempotent(env, deployment_args: ContractDeploymentArgs) -> Address;

    /// Upload WASM and deploy in one call
    pub fn upload_and_deploy(env, wasm_bytes, salt, constructor_args) -> Address;

    /// Compute the deterministic address without deploying
    pub fn get_deployed_address(env, salt, wasm_hash, constructor_args) -> Address;
}

pub struct ContractDeploymentArgs {
    wasm_hash: BytesN<32>,
    salt: BytesN<32>,
    constructor_args: Vec<Val>,
}
```

### Deterministic Salt Derivation

The factory derives the final salt by hashing `input_salt + wasm_hash + constructor_args`:
```rust
fn derive_salt(env, input_salt, wasm_hash, constructor_args) -> BytesN<32> {
    let mut bytes = Bytes::new(env);
    bytes.append(&input_salt.into());
    bytes.append(&wasm_hash.clone().into());
    for arg in constructor_args.iter() {
        bytes.append(&arg.to_xdr(env));
    }
    env.crypto().sha256(&bytes).into()
}
```

### Security Focus Areas

- No access control — anyone can deploy.
- `deploy_idempotent` checks existence by calling `is_deployed()` on the tentative address. If the contract exists but doesn't implement `is_deployed`, this silently fails and attempts a new deploy.
- Constructor arguments are included in the salt derivation — same arguments always produce the same address.

### Files

| File | Description |
|------|-------------|
| `contracts/contract-factory/src/lib.rs` | Factory implementation |
| `contracts/contract-factory/src/test.rs` | Tests (refactored) |

---

## 9. Wallet Address Initialization Locking (PR #89)

### Description

Locks the wallet contract address to its initialization parameters. This prevents address confusion attacks where a contract could be deployed at a known address but initialized with different parameters than expected.

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account/src/account.rs` | Initialization changes |

---

## 10. Upgradeable Contract Enhancements

### Description

The upgrade system was enhanced to support two-phase upgrades with data migration, enabling the v1→v2 upgrade path.

### Two-Phase Upgrade

```rust
// contracts/upgradeable/src/lib.rs

// Phase 1: Swap WASM (sets MIGRATING = true)
pub fn upgrade(env, new_wasm_hash);

// Phase 2: Run migration (sets MIGRATING = false, bumps version)
pub fn migrate(env, migration_data);
```

The `MIGRATING` flag in instance storage acts as a guard:
- `upgrade()` sets `MIGRATING = true`.
- `migrate()` checks `MIGRATING == true` before proceeding and sets it to `false` on completion.
- This prevents calling `migrate()` without a preceding `upgrade()`.

Both operations require admin authorization via `_require_auth_upgrade()`.

Events are emitted: `UPGRADE_STARTED` and `UPGRADE_COMPLETED`.

### Files

| File | Description |
|------|-------------|
| `contracts/upgradeable/src/lib.rs` | Two-phase upgrade framework, macros |

---

## 11. Interface Crate Restructuring (PRs #84, #85)

### Description

Shared types and traits were moved from the smart-account crate into the `smart-account-interfaces` crate. This enables external consumers (policies, plugins) to import types without depending on the full smart account contract.

### Changes

- `SignerRole`, `SignerKey`, `Signer`, `SignerPolicy`, and all related types moved to `smart-account-interfaces/src/auth/types.rs`.
- `SmartAccountError` enum moved to `smart-account-interfaces/src/error.rs`.
- `SmartAccountInterface` trait moved to `smart-account-interfaces/src/account.rs`.
- `SmartAccountPlugin` trait moved to `smart-account-interfaces/src/plugin.rs`.
- `SmartAccountPolicy` trait moved to `smart-account-interfaces/src/auth/policy/interface.rs`.
- Client types exposed for external consumers (PR #85).

### Files

| File | Description |
|------|-------------|
| `contracts/smart-account-interfaces/src/auth/types.rs` | All shared types |
| `contracts/smart-account-interfaces/src/error.rs` | Error enum |
| `contracts/smart-account-interfaces/src/account.rs` | Account trait |
| `contracts/smart-account-interfaces/src/lib.rs` | Re-exports |

---

## 12. Other Changes (PRs #86, #87, #90, #100)

### Halborn Security Review Documentation (PR #87)

Added the v1 Halborn security review PDF to the repository at `security/reviews/Stellar_Smart_Account_Oct_2025.pdf`.

### Testing Contract Enhancements (PRs #86, #90)

- **PR #86**: Increased scenario complexity in the `hello-world` testing contract to better exercise smart account authorization paths.
- **PR #90**: Added a duplicated auth function to the testing contract for testing edge cases where the same function is authorized multiple times.

These are test-only changes that do not affect production contract code.

### Documentation Update for V2 (PR #100)

Updated `README.md` and `contracts/smart-account/README.md` to reflect v2 features including spending limits, signer expiration, new signer types, and migration. Updated `security/threat-model.md` with minor adjustments.

---

## 13. Removed Features

### TimeWindowPolicy

The `TimeWindowPolicy` (formerly `TimeBasedPolicy`) was removed from the policy system. In v1 it allowed restricting a signer to a time window (`not_before`, `not_after`). This has been replaced by the signer expiration feature for time-based restrictions.

**File removed:** `contracts/smart-account/src/auth/policy/time_based.rs`

### TypeScript Examples and Packages

The following directories were removed entirely:
- `examples/` — TypeScript example scripts
- `packages/factory/` — TypeScript factory bindings
- `packages/smart_account/` — TypeScript smart account bindings

These were replaced by the `bindings/` directory (auto-generated TypeScript bindings).

---

## 14. Type System Evolution — V1 vs V2

| Type | V1 | V2 |
|------|-----|-----|
| `SignerRole` | `Admin \| Standard(Vec<SignerPolicy>)` | `Admin \| Standard(Option<Vec<SignerPolicy>>, u64)` |
| `SignerKey` | `Ed25519(BytesN<32>) \| Secp256r1(Bytes)` | `Ed25519(BytesN<32>) \| Secp256r1(BytesN<65>) \| Webauthn(Bytes) \| Multisig(BytesN<32>)` |
| `Signer` | `Ed25519(_, role) \| Secp256r1(_, role)` | `Ed25519(_, role) \| Secp256r1(_, role) \| Webauthn(_, role) \| Multisig(_, role)` |
| `SignerPolicy` | `TimeWindowPolicy(_) \| ExternalValidatorPolicy(_)` | `ExternalValidatorPolicy(_) \| TokenTransferPolicy(_)` |
| `SignerProof` | `Ed25519(_) \| Secp256r1(_)` | `Ed25519(_) \| Secp256r1(_) \| Webauthn(_) \| Multisig(_)` |
| `SpendTrackerKey` | *(did not exist)* | `TokenSpend(BytesN<32>, SignerKey)` |

---

## 15. New Error Codes

| Code | Name | Context |
|------|------|---------|
| 23 | `SignerExpired` | Signer expiration check failed |
| 44 | `ClientDataJsonIncorrectChallenge` | WebAuthn challenge mismatch |
| 45 | `InvalidWebauthnClientDataJson` | WebAuthn client data parsing failure |
| 46 | `MultisigThresholdNotMet` | Insufficient multisig member signatures |
| 47 | `MultisigInvalidThreshold` | Threshold is 0 or > member count |
| 48 | `MultisigMemberNotFound` | Proof references non-existent member |
| 49 | `MultisigDuplicatedMember` | Duplicate member in multisig configuration |
| 80 | `InvalidPolicy` | TokenTransferPolicy limit <= 0 |
| 82 | `InvalidNotAfterTime` | TokenTransferPolicy expiration in the past |
| 1101 | `MigrationVersionMismatch` | Migration data doesn't match contract version |

---

## 16. Test Coverage

| Test File | Lines | Feature |
|-----------|-------|---------|
| `tests/token_transfer_policy_test.rs` | ~700 | Spending limits, windows, recipients, expiration |
| `tests/upgrade_test.rs` | ~1,050 | V1→V2 migration, two-phase upgrade |
| `tests/expiring_signer_test.rs` | ~428 | Signer expiration at all layers |
| `tests/multisig_test.rs` | ~394 | M-of-N threshold verification |
| `tests/secp256r1_signer_test.rs` | ~255 | Raw P-256 signature verification |
| `tests/webauthn_signer_test.rs` | ~94 | WebAuthn/Passkey authentication |
| `tests/auth_test.rs` | refactored | Updated for new signer types |
| `tests/signer_management_test.rs` | refactored | Updated for expiration |
| `tests/admin_downgrade_test.rs` | refactored | Updated for new role structure |
| `tests/policy_test.rs` | refactored | Updated for new policy types |

WASM test fixtures: `testdata/smart_account_v1.wasm` (32 KB) and `testdata/smart_account_v2.wasm` (54 KB).

---

## 17. Key Files for Auditor Review

### Priority 1 — New Feature Implementations

| File | What to review |
|------|---------------|
| `contracts/smart-account/src/auth/policy/token_transfer.rs` | Spending limit authorization logic, overflow handling, window resets |
| `contracts/smart-account/src/auth/permissions.rs` | Policy dispatch, expiration defense-in-depth, authorization check traits |
| `contracts/smart-account/src/auth/core/authorizer.rs` | Signature verification orchestration, early expiration rejection |
| `contracts/smart-account/src/migration/v1_to_v2.rs` | Migration conversion logic |
| `contracts/smart-account/src/migration/v1_types.rs` | V1 XDR-compatible type definitions |
| `contracts/smart-account/src/migration/mod.rs` | Version dispatch |

### Priority 2 — New Signer Types

| File | What to review |
|------|---------------|
| `contracts/smart-account/src/auth/signers/webauthn.rs` | WebAuthn signature verification, challenge validation |
| `contracts/smart-account/src/auth/signers/multisig.rs` | Threshold verification, member lookup |
| `contracts/smart-account/src/auth/signers/secp256r1.rs` | Raw P-256 verification |

### Priority 3 — Infrastructure

| File | What to review |
|------|---------------|
| `contracts/smart-account/src/account.rs` | Signer lifecycle, policy callbacks, duplicate detection |
| `contracts/smart-account-interfaces/src/auth/types.rs` | All type definitions |
| `contracts/smart-account-interfaces/src/error.rs` | Error codes |
| `contracts/contract-factory/src/lib.rs` | Permissionless deployment, salt derivation |
| `contracts/upgradeable/src/lib.rs` | Two-phase upgrade mechanism |
