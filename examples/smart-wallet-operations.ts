import { Keypair, BASE_FEE, hash, nativeToScVal } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { Client as FactoryClient } from "factory";
import {
  Client as SmartWalletClient,
  Signer,
  SignerKey,
  SignerProof,
  Secp256r1Signer,
  Secp256r1Signature,
  xdr,
} from "smart_wallet";
import {
  FACTORY_WASM_HASH,
  ADMIN_SIGNER_KEYPAIR,
  ROOT_KEYPAIR,
  DEPLOYER_KEYPAIR,
  DELEGATED_SIGNER_KEYPAIR,
  SW_WASM_HASH,
  CONSTRUCTOR_FUNC,
  RPC_URL,
  NETWORK,
  TREASURY_KEYPAIR,
  HELLO_WORLD_CONTRACT_ID,
} from "./consts.js";
import {
  AssembledTransaction,
  basicNodeSigner,
} from "@stellar/stellar-sdk/contract";
import { Server } from "@stellar/stellar-sdk/rpc";
import { printAuthEntries } from "./utils.js";

/**
 * Example TypeScript application demonstrating smart wallet deployment and usage
 *
 * This example shows:
 * 1. Factory contract deployment with role-based access control
 * 2. Smart wallet deployment using the factory
 * 3. Signer management (add Ed25519 and Secp256r1/passkey signers)
 * 4. WebAuthn/passkey integration for authentication
 * 5. Transaction signing and submission with multiple signer types
 */

/**
 * Utility function to confirm transaction completion
 */
async function confirmTransaction(
  hash: string,
  operationName: string
): Promise<void> {
  const server = new Server(RPC_URL);
  let status;
  do {
    const tx = await server.getTransaction(hash);
    status = tx.status;
  } while (status == "NOT_FOUND");

  if (status === "FAILED") {
    throw new Error(`${operationName} failed`);
  }
}

/**
 * Utility function to authorize transaction entries with smart wallet
 */
async function authorizeWithSmartWallet(
  tx: any,
  smartWalletContractId: string,
  signerKeypair: Keypair,
  smartWalletClient: SmartWalletClient
): Promise<void> {
  const server = new Server(RPC_URL);
  await tx.signAuthEntries({
    address: smartWalletContractId,
    authorizeEntry: async (entry: any) => {
      const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
      const credentials = clone.credentials().address();

      let expiration = credentials.signatureExpirationLedger();

      if (!expiration) {
        const { sequence } = await server.getLatestLedger();
        expiration = sequence + 300 / 5; // assumes 5 second ledger time
      }
      credentials.signatureExpirationLedger(expiration);
      const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
        new xdr.HashIdPreimageSorobanAuthorization({
          networkId: hash(Buffer.from(NETWORK)),
          nonce: credentials.nonce(),
          signatureExpirationLedger: credentials.signatureExpirationLedger(),
          invocation: clone.rootInvocation(),
        })
      );
      const payload = hash(preimage.toXDR());
      let key: SignerKey;
      let val: SignerProof | undefined;
      const signature = signerKeypair.sign(payload);
      const rawPublicKey = signerKeypair.rawPublicKey();
      if (Uint8Array.from(rawPublicKey).length !== 32) {
        throw new Error(
          "Invalid public key. It should be 32 bytes long, but is " +
            rawPublicKey.length
        );
      }
      if (Uint8Array.from(signature).length !== 64) {
        throw new Error(
          "Invalid signature. It should be 64 bytes long, but is " +
            signature.length
        );
      }
      key = {
        tag: "Ed25519",
        values: [rawPublicKey],
      };
      val = {
        tag: "Ed25519",
        values: [signature],
      };
      const scKeyType = xdr.ScSpecTypeDef.scSpecTypeUdt(
        new xdr.ScSpecTypeUdt({ name: "SignerKey" })
      );
      const scValType = xdr.ScSpecTypeDef.scSpecTypeUdt(
        new xdr.ScSpecTypeUdt({ name: "SignerProof" })
      );
      const scKey = smartWalletClient.spec.nativeToScVal(key, scKeyType);
      const scVal = val
        ? smartWalletClient.spec.nativeToScVal(val, scValType)
        : xdr.ScVal.scvVoid();
      const scEntry = new xdr.ScMapEntry({
        key: scKey,
        val: scVal,
      });

      switch (credentials.signature().switch().name) {
        case "scvVoid":
          credentials.signature(
            xdr.ScVal.scvVec([xdr.ScVal.scvMap([scEntry])])
          );
          break;
        case "scvVec":
          // Add the new signature to the existing map
          credentials.signature().vec()?.[0].map()?.push(scEntry);

          credentials
            .signature()
            .vec()?.[0]
            .map()
            ?.sort((a, b) => {
              return (
                a.key().vec()![0].sym() + a.key().vec()![1].toXDR().join("")
              ).localeCompare(
                b.key().vec()![0].sym() + b.key().vec()![1].toXDR().join("")
              );
            });
          break;
        default:
          throw new Error("Unsupported signature");
      }
      return clone;
    },
  });
}

/**
 * Step 1: Deploy the ContractFactory
 */
async function deployFactory(): Promise<string> {
  console.log("\n" + "=".repeat(60));
  console.log("🏭 STEP 1: DEPLOYING CONTRACT FACTORY");
  console.log("=".repeat(60));

  try {
    const deployTx = await FactoryClient.deploy(
      { admin: ROOT_KEYPAIR.publicKey() },
      {
        wasmHash: FACTORY_WASM_HASH,
        salt: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
        networkPassphrase: NETWORK,
        fee: BASE_FEE,
        rpcUrl: RPC_URL,
        publicKey: ROOT_KEYPAIR.publicKey(),
      }
    );

    await deployTx.simulate();
    await deployTx.sign(basicNodeSigner(ROOT_KEYPAIR, NETWORK));
    const result = await deployTx.send();
    const hash = result.sendTransactionResponse?.hash;
    if (!hash) {
      throw new Error("Factory deployment failed: " + JSON.stringify(result));
    }

    console.log("📤 Transaction submitted with hash:", hash);
    await confirmTransaction(hash, "Factory deployment");

    const contractId = deployTx.result.options.contractId;

    console.log("✅ Factory deployed successfully");
    console.log("📍 Factory contract ID:", contractId);

    return contractId;
  } catch (error) {
    console.error("❌ Factory deployment failed:", error);
    throw error;
  }
}

/**
 * Step 2: Grant deployer role to an address
 */
async function grantDeployerRole(factoryContractId: string): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("🔑 STEP 2: GRANTING DEPLOYER ROLE");
  console.log("=".repeat(60));

  const factoryClient = new FactoryClient({
    contractId: factoryContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const grantRoleTx = await factoryClient.grant_role(
      {
        caller: ROOT_KEYPAIR.publicKey(),
        account: DEPLOYER_KEYPAIR.publicKey(),
        role: "deployer",
      },
      {
        simulate: true,
      }
    );

    printAuthEntries(grantRoleTx);

    await grantRoleTx.signAuthEntries({
      address: ROOT_KEYPAIR.publicKey(),
      ...basicNodeSigner(ROOT_KEYPAIR, NETWORK),
    });
    await grantRoleTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    const result = await grantRoleTx.send();
    const hash = result.sendTransactionResponse?.hash;
    if (!hash) {
      throw new Error("Grant role failed: " + JSON.stringify(result, null, 2));
    }

    console.log("📤 Transaction submitted with hash:", hash);
    await confirmTransaction(hash, "Grant role");

    console.log("✅ Deployer role granted successfully");
    console.log("🔗 Deployer account:", DEPLOYER_KEYPAIR.publicKey());
  } catch (error) {
    console.error("❌ Failed to grant deployer role:", error);
    throw error;
  }
}

/**
 * Step 3: Deploy a smart wallet using the factory
 */
async function deploySmartWallet(factoryContractId: string): Promise<string> {
  console.log("\n" + "=".repeat(60));
  console.log("💼 STEP 3: DEPLOYING SMART WALLET");
  console.log("=".repeat(60));

  const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));

  const factoryClient = new FactoryClient({
    contractId: factoryContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const addressTx = await factoryClient.get_deployed_address({ salt });
    const predictedAddress = addressTx.result;
    console.log("📍 Predicted smart wallet address:", predictedAddress);

    const constructor_args = {
      signers: [createAdminSignerFromKeypair(ADMIN_SIGNER_KEYPAIR)],
    };
    const smartWalletClient = new SmartWalletClient({
      contractId: predictedAddress,
      networkPassphrase: NETWORK,
      rpcUrl: RPC_URL,
      allowHttp: false,
      publicKey: TREASURY_KEYPAIR.publicKey(),
    });

    const deployTx = await factoryClient.deploy(
      {
        caller: DEPLOYER_KEYPAIR.publicKey(),
        wasm_hash: Buffer.from(SW_WASM_HASH, "hex"),
        salt: salt,
        constructor_args: smartWalletClient.spec.funcArgsToScVals(
          CONSTRUCTOR_FUNC,
          constructor_args
        ),
      },
      {
        simulate: true,
      }
    );

    printAuthEntries(deployTx);
    await deployTx.signAuthEntries({
      address: DEPLOYER_KEYPAIR.publicKey(),
      ...basicNodeSigner(DEPLOYER_KEYPAIR, NETWORK),
    });
    await deployTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    await deployTx.simulate();
    const result = await deployTx.send();
    const hash = result.sendTransactionResponse?.hash;
    if (!hash) {
      throw new Error(
        "Smart wallet deployment failed: " + JSON.stringify(result)
      );
    }

    console.log("📤 Transaction submitted with hash:", hash);
    await confirmTransaction(hash, "Smart wallet deployment");

    const contractId = deployTx.result;

    console.log("✅ Smart wallet deployed successfully");
    console.log("📍 Smart wallet contract ID:", contractId);

    return contractId;
  } catch (error) {
    console.error("❌ Smart wallet deployment failed:", error);
    throw error;
  }
}

/**
 * Step 4: Add additional Ed25519 signer to the smart wallet
 */
async function addEd25519Signer(smartWalletContractId: string): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("➕ STEP 4: ADDING ED25519 SIGNER TO SMART WALLET");
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const addSignerTx = await smartWalletClient.add_signer(
      {
        signer: {
          tag: "Ed25519",
          values: [
            {
              public_key: Buffer.from(DELEGATED_SIGNER_KEYPAIR.rawPublicKey()),
            },
            { tag: "Standard", values: undefined },
          ] as const,
        },
      },
      {
        simulate: true,
      }
    );

    printAuthEntries(addSignerTx);
    await authorizeWithSmartWallet(
      addSignerTx,
      smartWalletContractId,
      ADMIN_SIGNER_KEYPAIR,
      smartWalletClient
    );
    await addSignerTx.simulate();
    await addSignerTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    const result = await addSignerTx.send();
    const txHash = result.sendTransactionResponse?.hash;
    if (!txHash) {
      throw new Error(
        "Add signer transaction failed: " + JSON.stringify(result)
      );
    }

    console.log("📤 Transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Add signer");

    console.log("✅ Ed25519 signer added successfully");
    console.log(
      "🔗 New signer public key:",
      DELEGATED_SIGNER_KEYPAIR.publicKey()
    );
  } catch (error) {
    console.error("❌ Failed to add Ed25519 signer:", error);
    throw error;
  }
}

/**
 * Step 5: Add passkey (Secp256r1) signer to the smart wallet
 */
async function addPasskeySigner(smartWalletContractId: string): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("🔐 STEP 5: ADDING PASSKEY (SECP256R1) SIGNER TO SMART WALLET");
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const passkeySigner = createPasskeySigner();
    
    console.log("🔑 Creating passkey signer with:");
    console.log("  Key ID:", Buffer.from((passkeySigner.values[0] as Secp256r1Signer).key_id).toString('hex'));
    console.log("  Public Key:", Buffer.from((passkeySigner.values[0] as Secp256r1Signer).public_key).toString('hex'));

    const addSignerTx = await smartWalletClient.add_signer(
      {
        signer: passkeySigner,
      },
      {
        simulate: true,
      }
    );

    printAuthEntries(addSignerTx);
    await authorizeWithSmartWallet(
      addSignerTx,
      smartWalletContractId,
      ADMIN_SIGNER_KEYPAIR,
      smartWalletClient
    );
    await addSignerTx.simulate();
    await addSignerTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    const result = await addSignerTx.send();
    const txHash = result.sendTransactionResponse?.hash;
    if (!txHash) {
      throw new Error(
        "Add passkey signer transaction failed: " + JSON.stringify(result)
      );
    }

    console.log("📤 Transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Add passkey signer");

    console.log("✅ Passkey signer added successfully");
    console.log("🔐 Passkey authentication is now enabled for this wallet");
    console.log("🔗 Credential ID:", Buffer.from((passkeySigner.values[0] as Secp256r1Signer).key_id).toString('hex'));
  } catch (error) {
    console.error("❌ Failed to add passkey signer:", error);
    throw error;
  }
}

/**
 * Step 6: Send a hello world transaction with smart wallet authorization
 */
async function sendHelloWorldTransactionWithSmartWalletAuth(
  smartWalletContractId: string,
  step: string
): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log(`🌍 STEP ${step}: SENDING HELLO WORLD TRANSACTION`);
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const helloWorldTx = await AssembledTransaction.build<string[]>({
      method: "hello",
      args: [
        nativeToScVal(smartWalletContractId, {
          type: "address",
        }),
      ],
      contractId: HELLO_WORLD_CONTRACT_ID,
      networkPassphrase: NETWORK,
      rpcUrl: RPC_URL,
      allowHttp: false,
      publicKey: TREASURY_KEYPAIR.publicKey(),
      parseResultXdr: (xdrVal: xdr.ScVal) => {
        const xdrVec = xdrVal.vec();
        if (!xdrVec) {
          throw new Error("Expected a vector");
        }
        return xdrVec
          .map((xdrItem) => xdrItem.str())
          .map((str) => str.toString());
      },
    });

    printAuthEntries(helloWorldTx);
    await authorizeWithSmartWallet(
      helloWorldTx,
      smartWalletContractId,
      DELEGATED_SIGNER_KEYPAIR,
      smartWalletClient
    );
    await helloWorldTx.simulate();
    await helloWorldTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    const result = await helloWorldTx.send();
    const txHash = result.sendTransactionResponse?.hash;
    if (!txHash) {
      throw new Error(
        "Hello world transaction failed: " + JSON.stringify(result)
      );
    }

    console.log("📤 Transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Hello world transaction");

    console.log("✅ Hello world transaction completed successfully");
  } catch (error) {
    console.error("❌ Failed to send hello world transaction:", error);
    throw error;
  }
}

/**
 * Step 7: Upgrade the smart wallet
 */
async function upgradeSmartWallet(
  smartWalletContractId: string
): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("⬆️ STEP 7: UPGRADING SMART WALLET");
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const upgradeTx = await smartWalletClient.upgrade(
      {
        new_wasm_hash: Buffer.from(SW_WASM_HASH, "hex"),
      },
      {
        simulate: true,
      }
    );

    printAuthEntries(upgradeTx);
    await authorizeWithSmartWallet(
      upgradeTx,
      smartWalletContractId,
      ADMIN_SIGNER_KEYPAIR,
      smartWalletClient
    );
    await upgradeTx.simulate();
    await upgradeTx.sign(basicNodeSigner(TREASURY_KEYPAIR, NETWORK));
    const result = await upgradeTx.send();
    const txHash = result.sendTransactionResponse?.hash;
    if (!txHash) {
      throw new Error(
        "Upgrade smart wallet transaction failed: " + JSON.stringify(result)
      );
    }

    console.log("📤 Transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Upgrade smart wallet");

    console.log("✅ Smart wallet upgraded successfully");
  } catch (error) {
    console.error("❌ Failed to upgrade smart wallet:", error);
    throw error;
  }
}

function createAdminSignerFromKeypair(adminSignerKeyPair: Keypair): Signer {
  return {
    tag: "Ed25519",
    values: [
      {
        public_key: Buffer.from(adminSignerKeyPair.rawPublicKey()),
      },
      { tag: "Admin", values: undefined },
    ] as const,
  };
}

/**
 * Create a Secp256r1 (passkey/WebAuthn) signer for testing
 */
function createPasskeySigner(): Signer {
  const testPublicKey = Buffer.from([
    0x04, 0x8d, 0x61, 0x7e, 0x65, 0xc9, 0x50, 0x8e, 0x64, 0xbc, 0xc5, 0x67, 0x3a, 0xc8,
    0x2a, 0x67, 0x99, 0xda, 0x3c, 0x14, 0x46, 0x68, 0x2c, 0x25, 0x8c, 0x46, 0x3f, 0xff,
    0xdf, 0x58, 0xdf, 0xd2, 0xfa, 0x3e, 0x6c, 0x37, 0x8b, 0x53, 0xd7, 0x95, 0xc4, 0xa4,
    0xdf, 0xfb, 0x41, 0x99, 0xed, 0xd7, 0x86, 0x2f, 0x23, 0xab, 0xaf, 0x02, 0x03, 0xb4,
    0xb8, 0x91, 0x1b, 0xa0, 0x56, 0x99, 0x94, 0xe1, 0x01,
  ]);
  
  const testCredentialId = Buffer.from([
    0x74, 0x65, 0x73, 0x74, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
    0x6c, 0x5f, 0x69, 0x64, 0x5f, 0x31,
  ]);

  const secp256r1Signer: Secp256r1Signer = {
    key_id: testCredentialId,
    public_key: testPublicKey,
  };

  return {
    tag: "Secp256r1",
    values: [
      secp256r1Signer,
      { tag: "Standard", values: undefined },
    ] as const,
  };
}

/**
 * Main example function demonstrating the complete workflow
 */
async function main() {
  console.log("🚀 STARTING SMART WALLET DEPLOYMENT EXAMPLE");
  console.log("🌐 Network:", NETWORK);
  console.log("🔗 RPC URL:", RPC_URL);
  console.log("\n🔑 Generated keypairs:");
  console.log("  Admin:", ROOT_KEYPAIR.publicKey());
  console.log("  Deployer:", DEPLOYER_KEYPAIR.publicKey());
  console.log("  Admin Signer:", ADMIN_SIGNER_KEYPAIR.publicKey());
  console.log("  Delegated Signer:", DELEGATED_SIGNER_KEYPAIR.publicKey());
  console.log("  Treasury:", TREASURY_KEYPAIR.publicKey());

  try {
    const factoryContractId = await deployFactory();
    await grantDeployerRole(factoryContractId);
    const smartWalletContractId = await deploySmartWallet(factoryContractId);
    await addEd25519Signer(smartWalletContractId);
    await addPasskeySigner(smartWalletContractId);
    await sendHelloWorldTransactionWithSmartWalletAuth(
      smartWalletContractId,
      "6"
    );
    await upgradeSmartWallet(smartWalletContractId);
    await sendHelloWorldTransactionWithSmartWalletAuth(
      smartWalletContractId,
      "8"
    );

    console.log("\n" + "=".repeat(60));
    console.log("📋 DEPLOYMENT SUMMARY");
    console.log("=".repeat(60));
    console.log("✅ All operations completed successfully!");
    console.log("🏭 Factory Contract ID:", factoryContractId);
    console.log("💼 Smart Wallet Contract ID:", smartWalletContractId);
    console.log("🔑 Admin Signer:", ADMIN_SIGNER_KEYPAIR.publicKey());
    console.log("🔗 Ed25519 Delegated Signer:", DELEGATED_SIGNER_KEYPAIR.publicKey());
    console.log("🔐 Passkey signer added with WebAuthn/Secp256r1 support");
  } catch (error) {
    console.error("❌ Example failed:", error);
    process.exit(1);
  }
}

main()
  .then(() => {
    console.log("\n🎉 Example completed successfully!");
  })
  .catch(console.error);

export { deployFactory, grantDeployerRole, deploySmartWallet, addEd25519Signer, addPasskeySigner, createPasskeySigner };
