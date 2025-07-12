import { Keypair, Networks, rpc, TransactionBuilder, BASE_FEE } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import { Client as FactoryClient } from '../packages/factory/src/index';
import { Client as SmartWalletClient, Signer, SignerRole, Ed25519Signer } from '../packages/smart_wallet/src/index';

/**
 * Example TypeScript application demonstrating smart wallet deployment and usage
 * 
 * This example shows:
 * 1. Factory contract deployment with role-based access control
 * 2. Smart wallet deployment using the factory
 * 3. Signer management (add, update, revoke)
 * 4. Placeholder for transaction signing and submission
 */

const NETWORK = Networks.TESTNET;
const RPC_URL = 'https://soroban-testnet.stellar.org';
const DEPLOYER_ROLE = 'deployer';

const server = new rpc.Server(RPC_URL);

/**
 * Step 1: Deploy the CrossmintContractFactory
 */
async function deployFactory(adminKeypair: Keypair): Promise<string> {
    console.log('🏭 Deploying CrossmintContractFactory...');
    
    const factoryWasmHash = Buffer.from('PLACEHOLDER_FACTORY_WASM_HASH', 'hex');
    
    const factoryClient = new FactoryClient({
        networkPassphrase: NETWORK,
        rpcUrl: RPC_URL,
        allowHttp: false,
    });

    try {
        const deployTx = await FactoryClient.deploy(
            { admin: adminKeypair.publicKey() },
            {
                wasmHash: factoryWasmHash,
                salt: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
                source: adminKeypair.publicKey(),
                networkPassphrase: NETWORK,
                fee: BASE_FEE,
            }
        );

        deployTx.sign(adminKeypair);
        const result = await deployTx.send();
        
        console.log('✅ Factory deployed successfully');
        console.log('📍 Factory contract ID:', result.contractId);
        
        return result.contractId!;
    } catch (error) {
        console.error('❌ Factory deployment failed:', error);
        throw error;
    }
}

/**
 * Step 2: Grant deployer role to an address
 */
async function grantDeployerRole(
    factoryContractId: string,
    adminKeypair: Keypair,
    deployerAddress: string
): Promise<void> {
    console.log('🔑 Granting deployer role...');
    
    const factoryClient = new FactoryClient({
        contractId: factoryContractId,
        networkPassphrase: NETWORK,
        rpcUrl: RPC_URL,
        allowHttp: false,
    });

    try {
        const grantRoleTx = await factoryClient.grant_role({
            caller: adminKeypair.publicKey(),
            account: deployerAddress,
            role: DEPLOYER_ROLE,
        });

        grantRoleTx.sign(adminKeypair);
        await grantRoleTx.send();
        
        console.log('✅ Deployer role granted to:', deployerAddress);
    } catch (error) {
        console.error('❌ Failed to grant deployer role:', error);
        throw error;
    }
}

/**
 * Step 3: Deploy a smart wallet using the factory
 */
async function deploySmartWallet(
    factoryContractId: string,
    deployerKeypair: Keypair,
    initialSigners: Signer[]
): Promise<string> {
    console.log('💼 Deploying smart wallet...');
    
    const smartWalletWasmHash = Buffer.from('PLACEHOLDER_SMART_WALLET_WASM_HASH', 'hex');
    const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
    
    const factoryClient = new FactoryClient({
        contractId: factoryContractId,
        networkPassphrase: NETWORK,
        rpcUrl: RPC_URL,
        allowHttp: false,
    });

    try {
        const addressTx = await factoryClient.get_deployed_address({ salt });
        const predictedAddress = addressTx.result;
        console.log('📍 Predicted smart wallet address:', predictedAddress);

        const deployTx = await factoryClient.deploy({
            caller: deployerKeypair.publicKey(),
            wasm_hash: smartWalletWasmHash,
            salt: salt,
            constructor_args: [initialSigners], // Smart wallet constructor expects signers array
        });

        deployTx.sign(deployerKeypair);
        const result = await deployTx.send();
        
        console.log('✅ Smart wallet deployed successfully');
        console.log('📍 Smart wallet contract ID:', result.contractId);
        
        return result.contractId!;
    } catch (error) {
        console.error('❌ Smart wallet deployment failed:', error);
        throw error;
    }
}

/**
 * Step 4: Create initial signers for the smart wallet
 */
function createInitialSigners(ownerKeypair: Keypair): Signer[] {
    console.log('👥 Creating initial signers...');
    
    const ed25519Signer: Ed25519Signer = {
        public_key: Buffer.from(ownerKeypair.rawPublicKey()),
    };

    const adminSigner: Signer = {
        tag: 'Ed25519',
        values: [ed25519Signer, { tag: 'Admin', values: undefined }] as const,
    };

    console.log('✅ Initial signers created');
    return [adminSigner];
}

/**
 * Step 5: Add additional signers to the smart wallet
 */
async function addSigner(
    smartWalletContractId: string,
    authorizerKeypair: Keypair,
    newSignerKeypair: Keypair,
    role: SignerRole
): Promise<void> {
    console.log('➕ Adding new signer to smart wallet...');
    
    const smartWalletClient = new SmartWalletClient({
        contractId: smartWalletContractId,
        networkPassphrase: NETWORK,
        rpcUrl: RPC_URL,
        allowHttp: false,
    });

    const newEd25519Signer: Ed25519Signer = {
        public_key: Buffer.from(newSignerKeypair.rawPublicKey()),
    };

    const newSigner: Signer = {
        tag: 'Ed25519',
        values: [newEd25519Signer, role] as const,
    };

    try {
        const addSignerTx = await smartWalletClient.add_signer({ signer: newSigner });
        
        
        console.log('⚠️  PLACEHOLDER: Transaction prepared but not signed');
        console.log('📝 TODO: Implement smart wallet authorization payload');
        console.log('🔗 New signer public key:', newSignerKeypair.publicKey());
        
    } catch (error) {
        console.error('❌ Failed to add signer:', error);
        throw error;
    }
}

/**
 * PLACEHOLDER: Send a transaction using the smart wallet
 * 
 * This is where you would implement the actual transaction signing and submission
 * using the smart wallet's custom authorization mechanism.
 */
async function sendTransactionWithSmartWallet(
    smartWalletContractId: string,
    signerKeypairs: Keypair[],
    destinationAddress: string,
    amount: string
): Promise<void> {
    console.log('💸 PLACEHOLDER: Sending transaction with smart wallet...');
    
    
    console.log('📝 TODO: Implement transaction construction');
    console.log('📝 TODO: Implement authorization payload creation');
    console.log('📝 TODO: Implement multi-signature collection');
    console.log('📝 TODO: Integrate with Stellar SDK transaction submission');
    
    console.log('🎯 Target destination:', destinationAddress);
    console.log('💰 Amount:', amount);
    console.log('👥 Available signers:', signerKeypairs.length);
}

/**
 * PLACEHOLDER: Custom authorization integration
 * 
 * This function would handle the smart wallet's custom authorization mechanism
 * as defined in the __check_auth function of the smart account contract.
 */
async function createAuthorizationPayload(
    smartWalletContractId: string,
    signerKeypairs: Keypair[],
    signaturePayload: Buffer
): Promise<any> {
    console.log('🔐 PLACEHOLDER: Creating authorization payload...');
    
    
    console.log('📝 TODO: Implement SignerKey creation');
    console.log('📝 TODO: Implement SignerProof generation');
    console.log('📝 TODO: Implement authorization payload mapping');
    
    return {
        signerProofs: new Map(), // Map<SignerKey, SignerProof>
    };
}

/**
 * Main example function demonstrating the complete workflow
 */
async function main() {
    console.log('🚀 Starting Smart Wallet Deployment Example');
    console.log('🌐 Network:', NETWORK);
    console.log('🔗 RPC URL:', RPC_URL);
    
    try {
        const adminKeypair = Keypair.random();
        const deployerKeypair = Keypair.random();
        const ownerKeypair = Keypair.random();
        const additionalSignerKeypair = Keypair.random();
        
        console.log('🔑 Generated keypairs:');
        console.log('  Admin:', adminKeypair.publicKey());
        console.log('  Deployer:', deployerKeypair.publicKey());
        console.log('  Owner:', ownerKeypair.publicKey());
        console.log('  Additional Signer:', additionalSignerKeypair.publicKey());
        
        const factoryContractId = await deployFactory(adminKeypair);
        
        await grantDeployerRole(factoryContractId, adminKeypair, deployerKeypair.publicKey());
        
        const initialSigners = createInitialSigners(ownerKeypair);
        
        const smartWalletContractId = await deploySmartWallet(
            factoryContractId,
            deployerKeypair,
            initialSigners
        );
        
        const standardRole: SignerRole = { tag: 'Standard', values: undefined };
        await addSigner(
            smartWalletContractId,
            ownerKeypair,
            additionalSignerKeypair,
            standardRole
        );
        
        await sendTransactionWithSmartWallet(
            smartWalletContractId,
            [ownerKeypair],
            Keypair.random().publicKey(), // Random destination
            '10' // 10 XLM
        );
        
        console.log('✅ Example completed successfully!');
        console.log('📋 Summary:');
        console.log('  Factory Contract ID:', factoryContractId);
        console.log('  Smart Wallet Contract ID:', smartWalletContractId);
        
    } catch (error) {
        console.error('❌ Example failed:', error);
        process.exit(1);
    }
}

export {
    deployFactory,
    grantDeployerRole,
    deploySmartWallet,
    createInitialSigners,
    addSigner,
    sendTransactionWithSmartWallet,
    createAuthorizationPayload,
};

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}
