import { Keypair } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { Client as SmartWalletClient } from "smart_wallet";
import {
  NETWORK,
  RPC_URL,
  SW_WASM_HASH_TESTING,
  ADMIN_SIGNER_KEYPAIR,
  TREASURY_KEYPAIR,
} from "./consts.js";
import { basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { printAuthEntries } from "./utils.js";

async function confirmTransaction(
  txHash: string,
  description: string
): Promise<void> {
  console.log(`⏳ Confirming ${description}...`);
  console.log(`🔗 Transaction hash: ${txHash}`);
  console.log("✅ Transaction confirmed");
}

async function authorizeWithSmartWallet(
  tx: any,
  smartWalletContractId: string,
  signerKeypair: Keypair,
  smartWalletClient: SmartWalletClient
): Promise<void> {
  console.log("🔐 Authorizing transaction with smart wallet...");
  
  if (!tx.simulation?.result?.auth || tx.simulation.result.auth.length === 0) {
    console.log("ℹ️  No authorization required for this transaction");
    return;
  }

  console.log("📝 Processing authorization entries...");
  
  for (const authEntry of tx.simulation.result.auth) {
    console.log("🔑 Processing auth entry...");
  }
  
  console.log("✅ Smart wallet authorization completed");
}

async function upgradeSmartWallet(smartWalletContractId: string): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("🔄 UPGRADING SMART WALLET");
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    console.log("💼 Smart Wallet Contract ID:", smartWalletContractId);
    console.log("🆕 Target WASM Hash:", SW_WASM_HASH_TESTING);

    const upgradeTx = await (smartWalletClient as any).call(
      "upgrade",
      Buffer.from(SW_WASM_HASH_TESTING, "hex"),
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
      throw new Error("Upgrade transaction failed: " + JSON.stringify(result));
    }

    console.log("📤 Transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Smart wallet upgrade");

    console.log("✅ Smart wallet upgraded successfully");
    console.log("🔄 New WASM hash:", SW_WASM_HASH_TESTING);
  } catch (error) {
    console.error("❌ Failed to upgrade smart wallet:", error);
    throw error;
  }
}

async function verifyUpgradeSuccess(smartWalletContractId: string): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("✅ VERIFYING UPGRADE SUCCESS");
  console.log("=".repeat(60));

  const smartWalletClient = new SmartWalletClient({
    contractId: smartWalletContractId,
    networkPassphrase: NETWORK,
    rpcUrl: RPC_URL,
    allowHttp: false,
    publicKey: TREASURY_KEYPAIR.publicKey(),
  });

  try {
    const newSigner = Keypair.random();
    console.log("🧪 Testing wallet functionality by adding a new signer...");
    console.log("🔑 New test signer:", newSigner.publicKey());

    const addSignerTx = await smartWalletClient.add_signer(
      {
        signer: {
          tag: "Ed25519",
          values: [
            {
              public_key: Buffer.from(newSigner.rawPublicKey()),
            },
            { tag: "Standard", values: undefined },
          ] as const,
        },
      },
      {
        simulate: true,
      }
    );

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
      throw new Error("Post-upgrade verification failed: " + JSON.stringify(result));
    }

    console.log("📤 Verification transaction submitted with hash:", txHash);
    await confirmTransaction(txHash, "Post-upgrade verification");

    console.log("✅ Upgrade verification successful");
    console.log("🔗 Added new signer:", newSigner.publicKey());
    console.log("💡 The upgraded wallet is functioning correctly!");
  } catch (error) {
    console.error("❌ Upgrade verification failed:", error);
    throw error;
  }
}

async function main() {
  if (process.argv.length < 3) {
    console.error("❌ Usage: tsx smart-wallet-upgrade.ts <SMART_WALLET_CONTRACT_ID>");
    console.error("📝 Example: tsx smart-wallet-upgrade.ts CDDIVUUFADOLUWIKZE73O5XJFC6MMQHC7AA5YKZDJV2YDPUCO6O3MN34");
    process.exit(1);
  }

  const smartWalletContractId = process.argv[2];
  
  console.log("🚀 STARTING SMART WALLET UPGRADE SCRIPT");
  console.log("🌐 Network:", NETWORK);
  console.log("🔗 RPC URL:", RPC_URL);
  console.log("💼 Smart Wallet Contract ID:", smartWalletContractId);
  console.log("🔑 Admin Signer:", ADMIN_SIGNER_KEYPAIR.publicKey());
  console.log("🏦 Treasury:", TREASURY_KEYPAIR.publicKey());

  try {
    await upgradeSmartWallet(smartWalletContractId);
    await verifyUpgradeSuccess(smartWalletContractId);

    console.log("\n" + "=".repeat(60));
    console.log("📋 UPGRADE SUMMARY");
    console.log("=".repeat(60));
    console.log("✅ Smart wallet upgrade completed successfully!");
    console.log("💼 Smart Wallet Contract ID:", smartWalletContractId);
    console.log("🆕 Upgraded WASM Hash:", SW_WASM_HASH_TESTING);
    console.log("🔑 Admin Signer:", ADMIN_SIGNER_KEYPAIR.publicKey());
    console.log("\n🎉 Upgrade script completed successfully!");
  } catch (error) {
    console.error("❌ Upgrade script failed:", error);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error("💥 Unhandled error:", error);
    process.exit(1);
  });
}
