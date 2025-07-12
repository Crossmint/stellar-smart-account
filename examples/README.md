# Stellar Smart Wallet Examples

This directory contains TypeScript examples demonstrating how to deploy and use Stellar Smart Wallets with the CrossmintContractFactory.

## Overview

The smart wallet system consists of two main components:

1. **CrossmintContractFactory** - A secure contract deployment factory with role-based access control
2. **SmartAccount** - A programmable account contract supporting multiple authentication methods

## Example: Smart Wallet Deployment

The main example (`smart-wallet-deployment.ts`) demonstrates:

### ✅ Implemented Features

1. **Factory Contract Deployment**
   - Deploy the CrossmintContractFactory with admin role
   - Role-based access control setup

2. **Role Management**
   - Grant deployer role to authorized addresses
   - Role verification and management

3. **Smart Wallet Deployment**
   - Deploy smart wallets using the factory
   - Deterministic address prediction
   - Initial signer configuration

4. **Signer Management**
   - Create Ed25519 signers with different roles (Admin, Standard, Restricted)
   - Add new signers to existing smart wallets
   - Role-based permission system

### 🚧 Placeholder Features (TODO)

The following features are prepared with placeholders and require additional implementation:

1. **Transaction Signing & Submission**
   ```typescript
   // TODO: Implement smart wallet authorization payload
   await sendTransactionWithSmartWallet(
     smartWalletContractId,
     [ownerKeypair],
     destinationAddress,
     amount
   );
   ```

2. **Custom Authorization Integration**
   ```typescript
   // TODO: Implement authorization payload structure
   const authPayload = await createAuthorizationPayload(
     smartWalletContractId,
     signerKeypairs,
     signaturePayload
   );
   ```

3. **Multi-Signature Collection**
   - Collect signatures from multiple authorized signers
   - Verify signature validity and permissions
   - Handle different signer types (Ed25519, Secp256r1, Policy)

4. **Stellar SDK Integration**
   - Build transactions with smart wallet as source
   - Integrate with Stellar SDK transaction submission
   - Handle transaction fees and sequence numbers

## Usage

### Prerequisites

```bash
# Install dependencies
npm install

# Build the TypeScript code
npm run build
```

### Running the Example

```bash
# Run with tsx (development)
npm run dev

# Or run compiled JavaScript
npm start
```

### Configuration

The example uses the following default configuration:

```typescript
const NETWORK = Networks.TESTNET;
const RPC_URL = 'https://soroban-testnet.stellar.org';
const DEPLOYER_ROLE = 'deployer';
```

## Key Components

### Factory Client

```typescript
import { Client as FactoryClient } from '../packages/factory/src/index.js';

const factoryClient = new FactoryClient({
  networkPassphrase: NETWORK,
  rpcUrl: RPC_URL,
  allowHttp: false,
});
```

### Smart Wallet Client

```typescript
import { Client as SmartWalletClient } from '../packages/smart_wallet/src/index.js';

const smartWalletClient = new SmartWalletClient({
  contractId: smartWalletContractId,
  networkPassphrase: NETWORK,
  rpcUrl: RPC_URL,
  allowHttp: false,
});
```

### Signer Creation

```typescript
const ed25519Signer: Ed25519Signer = {
  public_key: Buffer.from(keypair.rawPublicKey()),
};

const signer: Signer = {
  tag: 'Ed25519',
  values: [ed25519Signer, { tag: 'Admin', values: undefined }],
};
```

## Next Steps

To complete the implementation, you'll need to:

1. **Obtain WASM Hashes**: Replace placeholder WASM hashes with actual deployed contract hashes
2. **Implement Authorization**: Complete the smart wallet authorization payload creation
3. **Add Transaction Logic**: Implement the transaction construction and submission
4. **Test Integration**: Test with actual Stellar testnet/mainnet

## Error Handling

The example includes comprehensive error handling for:

- Contract deployment failures
- Role assignment errors
- Signer management issues
- Network connectivity problems

## Security Considerations

- Private keys are generated randomly for demonstration
- In production, use secure key management
- Validate all inputs and permissions
- Test thoroughly on testnet before mainnet deployment

## Support

For questions or issues, please refer to the main repository documentation or create an issue.
