## Storage Strategy

To minimize per-call fees while keeping important state durable:
- Plugins registry (PLUGINS_KEY): Instance storage. It is read on every call inside __check_auth, so bundling it with the contract entry avoids extra reads.
- Signers (SignerKey -> Signer): Persistent storage. Signers are long-lived and can be numerous; keeping them persistent avoids bloating the contract entry.
- Admin count (ADMIN_COUNT_KEY): Persistent storage.
- Migration flag (MIGRATING): Instance storage.

Rationale:
- Instance storage is automatically loaded with the contract entry and is ideal for small, frequently accessed values (subject to the ledger entry size limit).
- Persistent storage is rented per byte over time and is suitable for larger or arbitrarily growing datasets.

Potential future optimizations:
- Early-exit plugin checks when no relevant auth contexts are present
- Maintain a lightweight “has_plugins” indicator for fast skip
- Track a dedicated set of “auth-hook” plugins if only some plugins need __check_auth callbacks

# Smart Account Contract Architecture

The Smart Account is a multi-signature account contract built on Soroban that provides enhanced security through role-based access control, policy-based authorization, and an extensible plugin system. It supports multiple cryptographic signature schemes, external policy delegation, and allows for fine-grained permission management suitable for both human users and AI agents.

## Overview

The Smart Account contract implements a flexible authentication system that combines:
- **Multiple signature schemes** (Ed25519 and Secp256r1/WebAuthn, extensible to others)
- **Role-based access control** (Admin, Standard with optional policies)
- **Policy-based restrictions** (time-based, contract allow/deny lists, external delegation)
- **Plugin architecture** with lifecycle hooks and authorization callbacks
- **Multi-signature support** with customizable authorization logic

This architecture enables sophisticated permission systems for enterprise blockchain applications, supporting use cases from simple multi-sig accounts to complex automated systems with AI agent integration, extensible plugins, and external policy delegation.

## Core Architecture

### Contract Structure

```
SmartAccount
├── SmartAccountInterface    # Administrative operations
│   ├── __constructor()      # Initialize with signers and plugins
│   ├── add_signer()        # Add new signer
│   ├── update_signer()     # Modify existing signer
│   ├── revoke_signer()     # Remove signer
│   ├── install_plugin()    # Install new plugin
│   └── uninstall_plugin()  # Remove plugin
└── CustomAccountInterface   # Soroban authentication
    └── __check_auth()      # Validate authorization and notify plugins
```

### Authentication System Architecture

```mermaid
graph TB
    subgraph "Smart Account Contract"
        SW[SmartAccount]
        SWI[SmartAccountInterface]
        CAI[CustomAccountInterface]
        
        SW --> SWI
        SW --> CAI
    end
    
    subgraph "Authentication Layer"
        CA[__check_auth]
        AP[SignatureProofs]
        
        CAI --> CA
        CA --> AP
    end
    
    subgraph "Signer System"
        S[Signer]
        SK[SignerKey]
        SR[SignerRole]
        
        AP --> S
        S --> SK
        S --> SR
    end
    
    subgraph "Verification Layer"
        SV[SignatureVerifier]
        SP[SignerProof]
        E25[Ed25519Signer]
        
        S --> SV
        SV --> SP
        SV --> E25
    end
    
    subgraph "Permission System"
        PC[AuthorizationCheck]
        SPol[SignerPolicy]
        TB[TimeWindowPolicy]
        AL[ContractAllowListPolicy]
        DL[ContractDenyListPolicy]
        
        SR --> PC
        PC --> SPol
        SPol --> TB
        SPol --> AL
        SPol --> DL
    end
```

## Plugin System

The Smart Account supports an extensible plugin architecture that allows external contracts to hook into the account's lifecycle and authorization flow.

### Plugin Interface

Plugins must implement the `SmartAccountPlugin` trait:

```rust
pub trait SmartAccountPlugin {
    fn on_install(env: &Env, source: Address);
    fn on_uninstall(env: &Env, source: Address);
    fn on_auth(env: &Env, source: Address, contexts: Vec<Context>);
}
```

### Plugin Lifecycle

1. **Installation**: Plugins are installed via `install_plugin()` or during contract initialization
2. **Authorization Hooks**: The `on_auth()` callback is invoked during every `__check_auth()` call
3. **Uninstallation**: Plugins can be removed via `uninstall_plugin()`

### Plugin Management
Note: If a plugin's on_uninstall hook fails during uninstallation, the account emits a PluginUninstallFailedEvent and proceeds with uninstall to avoid lock-in scenarios.

```rust
// Install a plugin (requires admin authorization)
SmartAccount::install_plugin(&env, plugin_address)?;

// Uninstall a plugin (requires admin authorization)
SmartAccount::uninstall_plugin(&env, plugin_address)?;

// Initialize account with plugins
SmartAccount::__constructor(
    env,
    vec![admin_signer],
    vec![analytics_plugin, logging_plugin]
);
```
- On uninstall, if a plugin's on_uninstall hook fails, the smart account emits a PluginUninstallFailedEvent and proceeds with uninstallation.

### Plugin Use Cases

- **Analytics and Monitoring**: Track account usage patterns
- **Compliance**: Implement regulatory requirements
- **Notifications**: Send alerts on specific operations
- **Rate Limiting**: Implement custom spending or operation limits
- **Audit Logging**: Maintain detailed operation logs

## External Policy Delegation

The Smart Account supports delegating authorization decisions to external policy contracts through the `ExternalPolicy` type.

### External Policy Interface

External policy contracts must implement the `SmartAccountPolicy` trait:

```rust
pub trait SmartAccountPolicy {
    fn on_add(env: &Env, source: Address);
    fn on_revoke(env: &Env, source: Address);
    fn is_authorized(env: &Env, source: Address, contexts: Vec<Context>) -> bool;
}
```

### External Policy Usage

```rust
// Create an external policy that delegates to a deny-list contract
let external_policy = ExternalPolicy {
    policy_address: deny_list_contract_address,
};

let restricted_signer = Signer::Ed25519(
    Ed25519Signer::new(signer_pubkey),
    SignerRole::Standard(vec![SignerPolicy::ExternalValidatorPolicy(external_policy)])
);
```

### Benefits of External Delegation

- **Reusability**: Share policy logic across multiple smart accounts
- **Upgradability**: Update policy logic without upgrading the smart account
- **Modularity**: Separate complex authorization logic into dedicated contracts
- **Composability**: Combine multiple external policies for complex rules

### Example: Deny-List Policy Contract

The repository includes an example deny-list policy contract that demonstrates external delegation:

```rust
#[contract]
pub struct DenyListPolicy;

#[contractimpl]
impl SmartAccountPolicy for DenyListPolicy {
    fn is_authorized(env: &Env, _source: Address, contexts: Vec<Context>) -> bool {
        let denied_contracts: Vec<Address> = 
            env.storage().instance().get(&CONTRACTS_SYMBOL).unwrap();
        
        contexts.iter().all(|context| match context {
            Context::Contract(contract) => !denied_contracts.contains(&contract.contract),
            _ => true,
        })
    }
    
    fn on_add(env: &Env, source: Address) {
        source.require_auth();
        env.storage().instance().set(&source, &0);
    }
    
    fn on_revoke(_env: &Env, _source: Address) {}
}
```

## Signer Types and Extensibility

### Current Signer Implementation

The system supports Ed25519 and Secp256r1 (WebAuthn/passkey) signatures with a design that allows easy extension:

```rust
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

pub enum Signer {
    Ed25519(Ed25519Signer, SignerRole),
    Secp256r1(Secp256r1Signer, SignerRole),
}

pub enum SignerProof {
    Ed25519(BytesN<64>),
    Secp256r1(Secp256r1Signature),
}
```

### Adding New Signer Types

To add a new signer type (e.g., WebAuthn, threshold signatures), follow this pattern:

1. **Define the signer struct** in `src/auth/signers/`:
```rust
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct NewSigner {
    pub public_key: BytesN<32>, // or appropriate key format
}
```

2. **Implement SignatureVerifier trait**:
```rust
impl SignatureVerifier for NewSigner {
    fn verify(&self, env: &Env, payload: &BytesN<32>, proof: &SignerProof) -> Result<(), Error> {
        // Implement signature verification logic
    }
}
```

3. **Add to the enums**:
```rust
// In SignerKey enum
NewSignerType(BytesN<32>),

// In Signer enum  
NewSignerType(NewSigner, SignerRole),

// In SignerProof enum
NewSignerType(BytesN<64>), // or appropriate proof format
```

4. **Update match statements** in the implementation files to handle the new variant.

### Signer Roles

```mermaid
graph TD
    SR[SignerRole] --> Admin[Admin]
    SR --> Standard[Standard with Policies]
    
    Admin --> |"Can authorize any operation"| AnyOp[Any Operation]
    Standard --> |"Cannot modify signers or upgrade"| LimitedOp[Limited Operations]
    Standard --> |"Subject to policies (if any)"| PolicyCheck[Policy Validation]
    
    PolicyCheck --> TB[TimeWindowPolicy]
    PolicyCheck --> AL[ContractAllowListPolicy]
    PolicyCheck --> DL[ContractDenyListPolicy]
```

## Policy System and Extensibility

### Current Policy Types

1. **TimeWindowPolicy**: Restricts signer validity to a time window
2. **ContractAllowListPolicy**: Only allows interactions with specified contracts
3. **ContractDenyListPolicy**: Blocks interactions with specified contracts
4. **ExternalValidatorPolicy**: Delegates authorization decisions to external policy contracts

### Policy Architecture

```mermaid
classDiagram
    class AuthorizationCheck {
        <<trait>>
        +is_authorized(env, context) bool
    }
    
    class PolicyCallback {
        <<trait>>
        +check(env) Result~(), Error~
    }
    
    class SignerPolicy {
        <<enum>>
        TimeWindowPolicy(TimeWindowPolicy)
        ContractDenyList(ContractDenyListPolicy)
        ContractAllowList(ContractAllowListPolicy)
        ExternalValidatorPolicy(ExternalPolicy)
    }
    
    class TimeWindowPolicy {
        +not_before: u64
        +not_after: u64
    }
    
    class ContractAllowListPolicy {
        +allowed_contracts: Vec~Address~
    }
    
    class ContractDenyListPolicy {
        +denied_contracts: Vec~Address~
    }
    
    class ExternalPolicy {
        +policy_address: Address
    }
    
    AuthorizationCheck <|.. SignerPolicy
    PolicyCallback <|.. SignerPolicy
    AuthorizationCheck <|.. TimeWindowPolicy
    AuthorizationCheck <|.. ContractAllowListPolicy
    AuthorizationCheck <|.. ContractDenyListPolicy
    AuthorizationCheck <|.. ExternalPolicy
    PolicyCallback <|.. TimeWindowPolicy
    PolicyCallback <|.. ContractAllowListPolicy
    PolicyCallback <|.. ContractDenyListPolicy
    PolicyCallback <|.. ExternalPolicy
    
    SignerPolicy --> TimeWindowPolicy
    SignerPolicy --> ContractAllowListPolicy
    SignerPolicy --> ContractDenyListPolicy
    SignerPolicy --> ExternalPolicy
```

### Adding New Policy Types

To add a new policy type (e.g., spending limits, rate limiting):

1. **Create the policy struct** in `src/auth/policy/`:
```rust
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct NewPolicy {
    // Policy-specific fields
}
```

2. **Implement required traits**:
```rust
impl AuthorizationCheck for NewPolicy {
    fn is_authorized(&self, env: &Env, context: &Context) -> bool {
        // Authorization logic
    }
}

impl PolicyCallback for NewPolicy {
    fn check(&self, env: &Env) -> Result<(), Error> {
        // Validation logic
    }
}
```

3. **Add to SignerPolicy enum**:
```rust
pub enum SignerPolicy {
    // ... existing variants
    ExternalValidatorPolicy(ExternalPolicy),
    NewPolicyType(NewPolicy),
}
```

4. **Update match statements** in the SignerPolicy implementations.

## Authentication Flow and Sequence

### Smart Account Validation Sequence

```mermaid
sequenceDiagram
    participant Client
    participant SorobanRuntime as Soroban Runtime
    participant SmartAccount as Smart Account
    participant Storage
    participant Signer
    participant Policy
    participant Plugin
    
    Client->>SorobanRuntime: Submit transaction with authorization
    SorobanRuntime->>SmartAccount: __check_auth(signature_payload, signature_proofs, auth_contexts)
    
    Note over SmartAccount: Step 1: Validate signature proofs
    SmartAccount->>SmartAccount: Check signature_proofs not empty
    
    Note over SmartAccount: Step 2: Pre-validate signer existence
    loop For each (signer_key, _) in signature_proofs
        SmartAccount->>Storage: has(signer_key)
        Storage-->>SmartAccount: Exists/Not found
        alt Signer not found
            SmartAccount-->>SorobanRuntime: Error: SignerNotFound
            SorobanRuntime-->>Client: Transaction failure
        end
    end
    
    Note over SmartAccount: Step 3: Verify signatures and cache signers
    loop For each (signer_key, proof) in signature_proofs
        SmartAccount->>Storage: get_signer(signer_key)
        Storage-->>SmartAccount: Return signer (safe after has() check)
        SmartAccount->>Signer: verify(signature_payload, proof)
        Signer-->>SmartAccount: Signature valid/invalid
        SmartAccount->>SmartAccount: Cache verified signer
    end
    
    Note over SmartAccount: Step 4: Check permissions with early exit
    loop For each auth_context
        SmartAccount->>SmartAccount: context_authorized = false
        loop For each (signer_key, _) in signature_proofs
            SmartAccount->>SmartAccount: Get cached signer
            SmartAccount->>Signer: role.is_authorized(context)
            
            alt Signer role is Admin
                Signer-->>SmartAccount: Authorized
                SmartAccount->>SmartAccount: context_authorized = true, break loop
            else Signer role is Standard
                Signer->>Signer: Check if operation is admin-only
                Signer-->>SmartAccount: Authorized/Denied
                alt Authorized
                    SmartAccount->>SmartAccount: context_authorized = true, break loop
                end
            else Signer role is Standard with policies
                loop For each policy in role
                    Signer->>Policy: is_authorized(env, context)
                    Policy-->>Signer: Policy result
                end
                Signer-->>SmartAccount: All policies passed/failed
                alt All policies passed
                    SmartAccount->>SmartAccount: context_authorized = true, break loop
                end
            end
        end
        alt context_authorized == false
            SmartAccount-->>SorobanRuntime: Error: InsufficientPermissions
            SorobanRuntime-->>Client: Transaction failure
        end
    end
    
    Note over SmartAccount: Step 5: Notify plugins
    loop For each installed plugin
        SmartAccount->>Plugin: on_auth(source, contexts)
        Plugin-->>SmartAccount: Plugin callback completed
    end
    
    SmartAccount-->>SorobanRuntime: Authorization successful
    SorobanRuntime-->>Client: Transaction success
```

## Gas Cost Analysis for `__check_auth`

### Gas Cost Formula

```
Total_Gas = Storage_Lookups(n) + Signature_Verification + Role_Checks + Policy_Enforcement

Where:
- n = Number of signers
- m = Number of authorization contexts  
- p = Number of policies per signer
- k = Contract list size (for allow/deny policies)
```

### Cost Factors

| Component | Complexity | Notes |
|-----------|------------|-------|
| **Storage Operations** | O(n) | Signer existence checks and retrieval |
| **Ed25519 Signatures** | O(1) | Baseline cost (1x) |
| **Secp256r1 Signatures** | O(1) | ~3x cost vs Ed25519 (includes SHA256 operations) |
| **Admin Role** | O(1) | Constant time authorization |
| **Standard Role** | O(m) | Address comparison per context |
| **Standard Role with Policies** | O(p × m) | Policy evaluation per context |
| **TimeBased Policy** | O(1) | Timestamp comparison |
| **Allow/Deny List Policy** | O(k) | Linear search through contract list |

### Optimization Recommendations

- Use Ed25519 over Secp256r1 for better performance
- Minimize signer count and policy complexity
- Keep contract allow/deny lists small (< 10 contracts)
- Prefer Admin role for high-frequency operations

### Sequence Numbers and Nonce Handling

The Smart Account relies on Soroban's built-in sequence number mechanism for replay protection:

1. **Soroban Account Sequence**: Each account has an incrementing sequence number
2. **Transaction Ordering**: Transactions must be submitted with correct sequence numbers
3. **Replay Protection**: Used sequence numbers cannot be reused
4. **Multi-sig Coordination**: All signers must agree on the same sequence number

The account does not implement custom nonce handling, instead leveraging Soroban's native account sequence system for transaction ordering and replay protection.

## Contract Upgradeability

The Smart Account supports contract upgrades through Soroban's built-in upgradeability mechanism, which allows updating the contract's WebAssembly bytecode without changing the contract address or requiring proxy patterns.

### Upgrade Mechanism

Unlike Ethereum's proxy pattern approach, Soroban contracts can be upgraded directly:

```rust
// Standard Soroban upgrade function (called by authorized admin)
env.deployer().update_current_contract_wasm(new_wasm_hash)
```

Key characteristics of Soroban contract upgrades:
- **Contract address remains unchanged** - No proxy contracts needed
- **State preservation** - Contract storage persists across upgrades
- **Atomic operation** - Upgrade succeeds or fails completely
- **Event emission** - System events track old and new WASM references

### Permission Requirements

Contract upgrades are controlled by the Smart Account's role-based permission system:

| Signer Role | Upgrade Permission | Description |
|-------------|-------------------|-------------|
| **Admin** | ✅ **Authorized** | Can authorize any operation including contract upgrades |
| **Standard** | ❌ **Denied** | Cannot modify signers or upgrade contracts |
| **Standard with Policies** | ❌ **Denied** | Subject to policy restrictions, typically cannot upgrade |

The upgrade authorization follows the same `__check_auth` flow as other operations:

```rust
// Admin signer can authorize upgrade operations
if signer.role() == SignerRole::Admin {
    // Authorized for any operation including upgrades
    return Ok(());
}
```

### Upgrade Process Flow

```mermaid
sequenceDiagram
    participant Admin as Admin Signer
    participant SW as Smart Account
    participant Soroban as Soroban Runtime
    participant Storage as Contract Storage
    
    Admin->>SW: Initiate upgrade with new WASM hash
    SW->>SW: __check_auth(upgrade_operation)
    
    Note over SW: Verify admin authorization
    SW->>SW: Check signer role == Admin
    SW->>Admin: Authorization confirmed
    
    SW->>Soroban: update_current_contract_wasm(new_wasm_hash)
    Soroban->>Storage: Preserve existing contract state
    Soroban->>Soroban: Replace WASM bytecode
    Soroban->>Soroban: Emit SYSTEM upgrade event
    
    Soroban-->>SW: Upgrade completed
    SW-->>Admin: Upgrade successful
    
    Note over SW: Contract address unchanged, state preserved
```

### Security Considerations

1. **Admin-Only Access**: Only Admin signers can perform upgrades, preventing unauthorized modifications
2. **Multi-Signature Support**: Multiple admin signatures can be required for upgrade authorization
3. **State Preservation**: Contract storage remains intact across upgrades
4. **Audit Trail**: Soroban system events provide upgrade history
5. **Rollback Capability**: Previous WASM versions can be redeployed if needed

### Integration with Factory Contract

The `CrossmintContractFactory` handles initial deployment but does not manage upgrades:
- **Initial Deployment**: Factory deploys contracts with role-based access control
- **Upgrade Management**: Individual Smart Account contracts handle their own upgrades
- **Permission Inheritance**: Admin roles established during deployment control upgrade access

This separation ensures that each Smart Account maintains autonomous control over its upgrade process while benefiting from the factory's standardized deployment patterns.

## Error Handling

The contract defines comprehensive error types organized by category:

- **Initialization Errors (0-9)**: Contract setup issues
- **Storage Errors (10-19)**: Data persistence problems  
- **Signer Management Errors (20-39)**: Signer lifecycle issues
- **Authentication & Signature Errors (40-59)**: Verification failures
- **Permission Errors (60-79)**: Authorization failures
- **Policy Errors (80-99)**: Policy validation issues
- **Generic Errors (100+)**: General purpose errors

## Usage Examples

### Basic Multi-Signature Setup

```rust
// Initialize account with admin and standard signers
let admin_signer = Signer::Ed25519(
    Ed25519Signer::new(admin_pubkey),
    SignerRole::Admin
);

let user_signer = Signer::Ed25519(
    Ed25519Signer::new(user_pubkey), 
    SignerRole::Standard
);

SmartAccount::__constructor(env, vec![admin_signer, user_signer], vec![]);
```

### Time-Restricted Signer

```rust
// Create a signer valid only during business hours
let time_policy = TimeWindowPolicy {
    not_before: business_start_timestamp,
    not_after: business_end_timestamp,
};

let restricted_signer = Signer::Ed25519(
    Ed25519Signer::new(temp_pubkey),
    SignerRole::Standard(vec![SignerPolicy::TimeWindowPolicy(time_policy)])
);

SmartAccount::add_signer(&env, restricted_signer)?;
```

### Contract-Specific Authorization

```rust
// Signer that can only interact with specific contracts
let allow_policy = ContractAllowListPolicy {
    allowed_contracts: vec![trading_contract_address, vault_contract_address],
};

let trading_signer = Signer::Ed25519(
    Ed25519Signer::new(trading_pubkey),
    SignerRole::Standard(vec![SignerPolicy::ContractAllowList(allow_policy)])
);
```

## AI Agent Integration

The Smart Account architecture is designed to support AI agent integration through:

- **Programmatic Signer Management**: Agents can be granted specific roles and policies
- **Time-Based Access**: Temporary access grants for automated operations
- **Contract-Specific Permissions**: Restrict agents to specific contract interactions
- **Policy Composition**: Combine multiple policies for complex authorization rules

This enables secure automation while maintaining fine-grained control over agent capabilities, making it suitable for both human users and AI-driven applications in the Crossmint ecosystem.

## Security Considerations

1. **Admin Signer Requirement**: At least one admin signer must exist to prevent lockout
2. **Policy Validation**: All policies are validated during signer creation
3. **Signature Verification**: Cryptographic proofs are verified before authorization
4. **Permission Layering**: Multiple authorization checks ensure proper access control
5. **Replay Protection**: Soroban's sequence number system prevents transaction replay

## Future Extensions

The modular architecture supports future enhancements:

- **Additional Signature Schemes**: WebAuthn, threshold signatures, multi-party signatures
- **Advanced Policies**: Spending limits, rate limiting, multi-party approval
- **Integration Patterns**: Cross-contract authorization, delegation mechanisms
- **Monitoring**: Event emission for audit trails and analytics
