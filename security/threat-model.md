# Smart Account STRIDE Threat Model

## Description

This threat model analyzes the security aspects of the Smart Account authentication flow, focusing on the critical `__check_auth` function that validates authorization for contract operations.

### Smart Account Authentication Flow

The following sequence diagram illustrates the complete authentication flow when a contract requires authorization from a Smart Account:

```mermaid
sequenceDiagram
    participant Actor
    participant ContractA as Contract A
    participant SorobanRuntime as Soroban Runtime
    participant SmartAccount as Smart Account Contract
    participant Storage as Contract Storage
    participant Signer as Signer Implementation
    participant Policy as Policy System
    
    Note over Actor, Policy: Transaction Initiation
    Actor->>ContractA: Submit transaction with authorization
    ContractA->>ContractA: Execute business logic
    ContractA->>SorobanRuntime: require_auth(smart_account_address)
    
    Note over SorobanRuntime, SmartAccount: Authorization Check
    SorobanRuntime->>SmartAccount: __check_auth(signature_payload, signature_proofs, auth_contexts)
    
    Note over SmartAccount: Step 1: Validate Input
    SmartAccount->>SmartAccount: Check signature_proofs not empty
    alt No signatures provided
        SmartAccount-->>SorobanRuntime: Error: NoProofsInAuthEntry
        SorobanRuntime-->>ContractA: Authorization failed
        ContractA-->>Actor: Transaction failed
        note right of Actor: End flow
    end
    
    Note over SmartAccount, Storage: Step 2: Pre-validate Signer Existence
    loop For each (signer_key, _) in signature_proofs
        SmartAccount->>Storage: has(signer_key)
        Storage-->>SmartAccount: Boolean result
        alt Signer not found
            SmartAccount-->>SorobanRuntime: Error: SignerNotFound
            SorobanRuntime-->>ContractA: Authorization failed
            ContractA-->>Actor: Transaction failed
            note right of Actor: End flow
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
                SmartAccount-->>SorobanRuntime: Error: SignatureVerificationFailed
                SorobanRuntime-->>ContractA: Authorization failed
                ContractA-->>Actor: Transaction failed
                note right of Actor: End flow
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
                        
                        alt Time-based Policy
                            Policy->>Policy: Check current_time >= not_before && current_time <= not_after
                            Policy-->>Signer: Time policy result
                        else Contract Allow List Policy
                            Policy->>Policy: Check if context.contract in allowed_contracts
                            Policy-->>Signer: Allow list policy result
                        else Contract Deny List Policy
                            Policy->>Policy: Check if context.contract NOT in denied_contracts
                            Policy-->>Signer: Deny list policy result
                        end
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
            SmartAccount-->>SorobanRuntime: Error: InsufficientPermissions
            SorobanRuntime-->>ContractA: Authorization failed
            ContractA-->>Actor: Transaction failed
            note right of Actor: End flow
        end
    end
    
    Note over SmartAccount, Actor: Success Flow
    SmartAccount-->>SorobanRuntime: Authorization successful
    SorobanRuntime-->>ContractA: Authorization granted
    ContractA->>ContractA: Continue business logic execution
    ContractA-->>Actor: Transaction successful
```

### Key Security Components

1. **Multi-layered Validation**: The system performs signature existence checks before expensive cryptographic operations
2. **Early Exit Optimization**: Authorization stops as soon as one valid signer is found for each context
3. **Role-based Authorization**: Admin, Standard, and Restricted roles with different permission levels
4. **Policy Enforcement**: Time-based, contract allow/deny list policies for fine-grained control
5. **Cryptographic Verification**: Support for Ed25519 and Secp256r1 signature schemes

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
<!-- Add spoofing issues here -->
</td>
</tr>
<tr>
<td>Tampering</td>
<td>
<!-- Add tampering issues here -->
</td>
</tr>
<tr>
<td>Repudiation</td>
<td>
<!-- Add repudiation issues here -->
</td>
</tr>
<tr>
<td>Information Disclosure</td>
<td>
<!-- Add information disclosure issues here -->
</td>
</tr>
<tr>
<td>Denial of Service</td>
<td>
<!-- Add denial of service issues here -->
</td>
</tr>
<tr>
<td>Elevation of Privilege</td>
<td>
<!-- Add elevation of privilege issues here -->
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