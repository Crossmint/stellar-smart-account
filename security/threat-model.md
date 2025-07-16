# Smart Account STRIDE Threat Model

## Description

### What is a Smart Account?

A **Smart Account** is an advanced account implementation built on Stellar's Soroban smart contract platform that provides programmable authorization logic through a custom smart contract. Unlike traditional Stellar accounts that rely solely on Ed25519 signatures and basic multisig thresholds, smart accounts implement Soroban's `CustomAccountInterface` to enable sophisticated, policy-driven authorization rules.

This smart account is an **upgradeable smart contract** that implements both the `SmartAccountInterface` (for account management operations) and Soroban's `CustomAccountInterface` (for transaction authorization). It leverages Stellar's account abstraction framework to decouple authentication logic from application-specific authorization rules, allowing for much more granular control over who can authorize what types of transactions.

The key innovation is moving from Stellar's traditional "signature + threshold" model to a **role-based, policy-driven authorization system** where different signers can have different permission levels and constraints.

### Key Features

#### 🔄 **Fully Authorized Upgradeability**
- Smart contract code can be upgraded through the standard signer permission system
- Upgrades require proper authorization from signers with sufficient permissions
- No special backdoors or admin keys - upgrades follow the same authorization rules as other operations

#### 👥 **Hierarchical Signer Types**

| Signer Type | Permissions & Capabilities |
|---|---|
| **Admin Signers** | • Can authorize any transaction for the wallet<br>• Full control over signer configuration (add, update, revoke signers)<br>• Can authorize contract upgrades<br>• Cannot be revoked (prevents account lockout) |
| **Standard Signers** | • Can authorize most transactions<br>• Cannot modify signer configuration or upgrade the contract<br>• Ideal for day-to-day operations while maintaining security boundaries |
| **Restricted Signers** | • Subject to a modular, policy-based permission system<br>• Ideal for security-sensitive scenarios requiring controlled access<br>• Perfect for delegating permissions to AI agents, automated systems, or third-party services<br>• Support for granular permissions such as:<br>&nbsp;&nbsp;- Token spending limits<br>&nbsp;&nbsp;- Contract interaction deny-listing<br>&nbsp;&nbsp;- Time-based restrictions<br>&nbsp;&nbsp;- Custom authorization policies<br>• Extensible framework for adding new permission types |

#### 🔐 **Multi-Signature Algorithm Support**

| Signature Algorithm | Features & Capabilities |
|---|---|
| **Ed25519 Signatures** | • Traditional cryptographic signatures<br>• Backward compatible with existing Stellar tooling |
| **Secp256r1 Signatures** | • Enables **Passkey/WebAuthn** authentication flows<br>• Provides better user experience through biometric authentication<br>• Supports hardware security keys and platform authenticators<br>• Eliminates the need for users to manage seed phrases |

This dual signature support allows the smart account to bridge traditional crypto workflows with modern web authentication standards, making it more accessible to mainstream users while maintaining the security guarantees expected in the Stellar ecosystem.

**Extensible Architecture**: The signer implementation follows a strategy pattern, making it easily extensible to support additional cryptographic algorithms. New signature schemes such as Secp256k1 or future cryptographic standards can be integrated without modifying the core authorization logic, ensuring the smart account remains adaptable to evolving security requirements.


### Smart Account Authentication Flow

#### Simplified Authorization Flow

The Smart Account implements a strict security model with the following core principles:

1. **Universal Authorization Requirement**: Every execution context (transaction operation) MUST be authorized by at least one signer with sufficient permissions
2. **Cryptographic Integrity**: All signatures provided MUST be cryptographically valid and verifiable
3. **Hierarchical Permission Model**: Authorization success depends on the signer's role and the operation being performed

**Step-by-Step Authorization Process:**

1. **Signature Validation Phase**
   - Verify all provided signatures are cryptographically correct (Ed25519 or Secp256r1)
   - Confirm all signing keys exist in the smart account's signer registry
   - Reject the entire transaction if any signature is invalid

2. **Authorization Check Phase**
   - For each execution context in the transaction:
     - Iterate through all verified signers until one with sufficient permissions is found
       - **Admin Signers**: Automatically authorized for all operations
       - **Standard Signers**: Authorized for non-admin operations only
       - **Restricted Signers**: Subject to policy evaluation (spending limits, time restrictions, etc.)
   - **Critical Security Guarantee**: If NO signer with sufficient permissions is found for ANY context, the entire transaction fails

3. **Early Exit Optimization**
   - Authorization stops immediately when the first valid signer is found for each context
   - This prevents unnecessary computation while maintaining security guarantees

**Security Model Summary:**
- **Fail-Safe Default**: Deny all operations unless explicitly authorized
- **No Partial Success**: All contexts must be authorized or the entire transaction fails
- **Cryptographic Foundation**: All authorization decisions are based on verified signatures using Stellar battle-tested cryptographic primitives
- **Role-Based Access Control**: Different signer types have different authorization capabilities

#### Complete Authentication Flow

The following sequence diagram illustrates the complete authentication flow when a contract requires authorization from a Smart Account:

```mermaid
sequenceDiagram
    participant User
    participant TokenContract as Token Contract
    participant Runtime as Soroban Runtime
    participant SmartAccount as Smart Account Contract
    participant Storage as Contract Storage
    participant Signer as Signer Implementation
    participant Policy as Policy System
    
    Note over User, Policy: Transaction Initiation
    User->>TokenContract: Submit transaction with authorization
    TokenContract->>TokenContract: Execute business logic
    TokenContract->>Runtime: require_auth(smart_account_address)
    
    Note over Runtime, SmartAccount: Authorization Check (Pre-validation)
    Runtime->>Runtime: Find authorized invocation tree matching require_auth call
    Runtime->>Runtime: Verify signature expiration (reject if expired)
    Runtime->>Runtime: Verify and consume nonce (must be unique)
    Runtime->>Runtime: Build signature payload preimage and compute SHA-256 hash
    Runtime->>SmartAccount: __check_auth(signature_payload, signature_proofs, auth_contexts)
    
    Note over SmartAccount: Step 1: Validate Input
    SmartAccount->>SmartAccount: Check signature_proofs not empty
    alt No signatures provided
        SmartAccount-->>Runtime: Error: NoProofsInAuthEntry
        Runtime-->>TokenContract: Authorization failed
        TokenContract-->>User: Transaction failed
        note right of User: End flow
    end
    
    Note over SmartAccount, Storage: Step 2: Pre-validate Signer Existence
    loop For each (signer_key, _) in signature_proofs
        SmartAccount->>Storage: has(signer_key)
        Storage-->>SmartAccount: Boolean result
        alt Signer not found
            SmartAccount-->>Runtime: Error: SignerNotFound
            Runtime-->>TokenContract: Authorization failed
            TokenContract-->>User: Transaction failed
            note right of User: End flow
        end
    end
    
    Note over SmartAccount, Signer: Step 3: Verify Signatures & Cache Signers
    loop For each (signer_key, proof) in signature_proofs
        SmartAccount->>Storage: get<SignerKey, Signer>(signer_key)
        Storage-->>SmartAccount: Return signer object
        SmartAccount->>Signer: verify(signature_payload, proof)
        
        alt Signature verification
            Signer->>Signer: Cryptographic signature validation
            alt Ed25519 signature
                Signer->>Signer: ed25519_verify(public_key, signature_payload, proof)
            else Secp256r1 signature
                Signer->>Signer: secp256r1_verify(public_key, signature_payload, proof)
            end
            
            alt Signature invalid
                Signer-->>SmartAccount: Error: SignatureVerificationFailed
                SmartAccount-->>Runtime: Error: SignatureVerificationFailed
                Runtime-->>TokenContract: Authorization failed
                TokenContract-->>User: Transaction failed
                note right of User: End flow
            else Signature valid
                Signer-->>SmartAccount: Signature verified
                SmartAccount->>SmartAccount: Cache verified signer
            end
        end
    end
    
    Note over SmartAccount, Policy: Step 4: Authorization Check with Early Exit
    loop For each auth_context in auth_contexts
        SmartAccount->>SmartAccount: context_authorized = false
        
        loop For each verified signer (early exit on success)
            SmartAccount->>SmartAccount: Get cached signer
            SmartAccount->>Signer: role.is_authorized(env, context)
            
            alt Admin Role
                Signer-->>SmartAccount: Always authorized
                SmartAccount->>SmartAccount: context_authorized = true
                SmartAccount->>SmartAccount: Break inner loop (early exit)
                
            else Standard Role
                Signer->>Signer: Check if operation is admin-only
                alt Admin operation (contract = current_contract_address)
                    Signer-->>SmartAccount: Not authorized
                else Non-admin operation
                    Signer-->>SmartAccount: Authorized
                    SmartAccount->>SmartAccount: context_authorized = true
                    SmartAccount->>SmartAccount: Break inner loop (early exit)
                end
                
            else Restricted Role
                Signer->>Signer: Check if admin operation
                alt Admin operation
                    Signer-->>SmartAccount: Not authorized (restricted signers cannot do admin ops)
                else Non-admin operation
                    loop For each policy in signer.role.policies
                        Signer->>Policy: policy.is_authorized(env, context)
                    end
                    
                    alt All policies passed
                        Signer-->>SmartAccount: Authorized
                        SmartAccount->>SmartAccount: context_authorized = true
                        SmartAccount->>SmartAccount: Break inner loop (early exit)
                    else Any policy failed
                        Signer-->>SmartAccount: Not authorized
                    end
                end
            end
        end
        
        alt context_authorized == false
            SmartAccount-->>Runtime: Error: InsufficientPermissions
            Runtime-->>TokenContract: Authorization failed
            TokenContract-->>User: Transaction failed
            note right of User: End flow
        end
    end
    
    Note over SmartAccount, User: Success Flow
    SmartAccount-->>Runtime: Authorization successful
    Runtime-->>TokenContract: Authorization granted
    TokenContract->>TokenContract: Continue business logic execution
    TokenContract-->>User: Transaction successful
```



## What can go wrong?

### STRIDE Reminders

| Mnemonic Threat | Definition | Question |
|---|---|---|
| Spoofing | The ability to impersonate another user or system component to gain unauthorized access. | Is the user who they say they are? |
| Tampering | Unauthorized alteration of data or code. | Has the data or code been modified in some way? |
| Repudiation | The ability for a system or user to deny having taken a certain action. | Is there enough data to "prove" the user took the action if they were to deny it? |
| Information Disclosure | The over-sharing of data expected to be kept private. | Is there anywhere where excessive data is being shared or controls are not properly in place to protect private information? |
| Denial of Service | The ability for an attacker to negatively affect the availability of a system. | Can someone, without authorization, impact the availability of the service or business? |
| Elevation of Privilege | The ability for an attacker to gain additional privileges and roles beyond what they initially were granted. | Are there ways for a user, without proper authentication (verifying identity) and authorization (verifying permission) to gain access to additional privileges, either through standard (normally legitimate) or illegitimate means? |

### Threat Table

<table>
<tr>
<th>Thread</th>
<th>Issues</th>
</tr>
<tr>
<td>Spoofing</td>
<td>
<strong>Spoof.1</strong> - (Authorization Flow) An attacker compromises a signer's private key (Ed25519 or Secp256r1) and impersonates them to authorize malicious transactions. <br>
<strong>Spoof.2</strong> - (WebAuthn Flow) An attacker performs a man-in-the-middle attack during WebAuthn/Passkey authentication, intercepting and replaying authentication challenges to spoof legitimate users. <br>
<strong>Spoof.3</strong> - (Contract Upgrade) An attacker creates a malicious smart contract that mimics the legitimate smart account interface and tricks users into interacting with it instead of the real contract. <br>
<strong>Spoof.4</strong> - (Signature Replay) An attacker captures valid signatures from previous transactions and attempts to replay them in new contexts to bypass authorization checks. <br>
<strong>Spoof.5</strong> - (Signer Impersonation) An attacker generates key pairs that could potentially collide with existing signer public keys, attempting to impersonate legitimate signers.
</td>
</tr>
<tr>
<td>Tampering</td>
<td>
<strong>Tamper.1</strong> - (Signature Payload) An attacker modifies the signature payload hash after signature generation but before verification, potentially allowing unauthorized operations to be executed. <br>
<strong>Tamper.2</strong> - (Contract Storage) An attacker exploits a vulnerability in the contract storage mechanism to modify signer data, policies, or authorization rules stored in the contract. <br>
<strong>Tamper.3</strong> - (Authorization Context) An attacker manipulates the authorization context parameters during the __check_auth call to bypass permission checks or escalate privileges. <br>
<strong>Tamper.4</strong> - (Policy Modification) A restricted signer finds a way to modify their own policy restrictions (spending limits, time constraints) to gain unauthorized access. <br>
<strong>Tamper.5</strong> - (Upgrade Tampering) An attacker intercepts and modifies upgrade transactions to deploy malicious contract code instead of legitimate upgrades. <br>
<strong>Tamper.6</strong> - (Nonce Manipulation) An attacker manipulates the nonce system to enable signature replay attacks or bypass transaction ordering constraints.
</td>
</tr>
<tr>
<td>Repudiation</td>
<td>
<strong>Repudiate.1</strong> - (Transaction Denial) A signer authorizes a high-value transaction but later denies having signed it, claiming their key was compromised, making it difficult to prove legitimate authorization. <br>
<strong>Repudiate.2</strong> - (Admin Action Denial) An admin signer performs critical operations (signer addition/removal, contract upgrades) but denies responsibility when questioned about the changes. <br>
<strong>Repudiate.3</strong> - (Policy Bypass) A restricted signer exploits policy loopholes to perform unauthorized actions but denies intentional policy violation, claiming the action was within their perceived permissions. <br>
<strong>Repudiate.4</strong> - (Upgrade Authorization) Multiple admin signers participate in a controversial contract upgrade but each denies being the primary authorizer, creating accountability gaps. <br>
<strong>Repudiate.5</strong> - (Signature Timestamp) Due to lack of precise timestamp logging, signers can deny the timing of their authorization, making it difficult to establish the sequence of events for audit purposes.
</td>
</tr>
<tr>
<td>Information Disclosure</td>
<td>
<strong>Info.1</strong> - (Signer Enumeration) An attacker analyzes on-chain transaction patterns to enumerate all signers associated with a smart account, revealing the account's security structure and potential high-value targets. <br>
<strong>Info.2</strong> - (Policy Revelation) By observing which transactions are authorized or rejected, an attacker can reverse-engineer the policy restrictions of restricted signers, learning spending limits, time constraints, and authorization patterns. <br>
<strong>Info.3</strong> - (Authorization Pattern Analysis) An attacker performs statistical analysis of authorization patterns to identify which signers are most active, their authorization frequency, and potential operational security patterns. <br>
<strong>Info.4</strong> - (WebAuthn Metadata Leakage) WebAuthn authentication flows may leak device information, user agent details, or biometric capabilities that could be used for targeted attacks. <br>
<strong>Info.5</strong> - (Storage Data Exposure) Contract storage queries reveal more information than necessary about internal signer configurations, policy parameters, or authorization state that could aid in attack planning. <br>
<strong>Info.6</strong> - (Signature Algorithm Disclosure) By analyzing signature formats, an attacker can determine which signature algorithms each signer uses, potentially targeting weaker cryptographic implementations.
</td>
</tr>
<tr>
<td>Denial of Service</td>
<td>
<strong>DoS.1</strong> - (Resource Exhaustion) An attacker submits transactions with maximum allowed signatures and complex authorization contexts to exhaust contract computational resources and prevent legitimate transactions. <br>
<strong>DoS.2</strong> - (Invalid Signature Flood) An attacker floods the smart account with transactions containing invalid signatures, forcing the contract to waste resources on signature verification failures. <br>
<strong>DoS.3</strong> - (Policy Evaluation Overload) An attacker targets restricted signers with transactions designed to trigger computationally expensive policy evaluations, overwhelming the contract's processing capacity. <br>
<strong>DoS.4</strong> - (Nonce Exhaustion) An attacker attempts to exhaust the nonce space or create nonce conflicts that prevent legitimate transactions from being processed. <br>
<strong>DoS.5</strong> - (Storage Bloat) An attacker exploits signer management functions to create excessive storage entries, potentially hitting storage limits and preventing new signers from being added. <br>
<strong>DoS.6</strong> - (Upgrade Lock) An attacker initiates but never completes upgrade transactions, potentially locking the contract in an intermediate state that prevents both normal operations and legitimate upgrades.
</td>
</tr>
<tr>
<td>Elevation of Privilege</td>
<td>
<strong>Elevation.1</strong> - (Role Escalation) A restricted signer exploits a vulnerability in the authorization logic to gain standard or admin privileges without proper authorization from existing admin signers. <br>
<strong>Elevation.2</strong> - (Policy Bypass) A restricted signer discovers a way to bypass policy restrictions (spending limits, time constraints, contract deny-lists) and perform unauthorized high-privilege operations. <br>
<strong>Elevation.3</strong> - (Upgrade Hijacking) A standard signer finds a way to authorize contract upgrades despite not having admin privileges, potentially installing malicious code or backdoors. <br>
<strong>Elevation.4</strong> - (Cross-Context Privilege) A signer with limited permissions in one context exploits the authorization system to gain broader permissions across multiple contexts within the same transaction. <br>
<strong>Elevation.5</strong> - (Signer Self-Elevation) A signer exploits the signer management system to modify their own role or permissions without authorization from admin signers. <br>
<strong>Elevation.6</strong> - (Emergency Access) An attacker exploits emergency or recovery mechanisms intended for legitimate account recovery to gain unauthorized admin access to the smart account. <br>
<strong>Elevation.7</strong> - (Contract Interface Confusion) An attacker exploits differences between the SmartAccountInterface and CustomAccountInterface to gain elevated privileges through interface confusion attacks.
</td>
</tr>
</table>

## What are we going to do about it?

## Did we do a good job?

### Has the data flow diagram been referenced since it was created?

<!-- Answer here -->

### Did the STRIDE model uncover any new design issues or concerns that had not been previously addressed or thought of?

<!-- Answer here -->

### Did the treatments identified in the "What are we going to do about it" section adequately address the issues identified?

<!-- Answer here -->

### Have additional issues been found after the threat model?

<!-- Answer here -->

### Any additional thoughts or insights on the threat modeling process that could help improve it next time?

<!-- Answer here -->