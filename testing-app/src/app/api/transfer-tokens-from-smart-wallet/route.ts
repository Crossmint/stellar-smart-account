import { RPC_URL } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import {
  SIGNER_1_WALLET,
  SWC_ADDRESS,
  SWC_WASM_HASH,
  TREASURY_WALLET,
  XLM_TESTNET_ADDRESS,
  XMUSD_CONTRACT_ADDRESS,
} from "@/lib/wallets";
import { Server } from "@stellar/stellar-sdk/rpc";
import {
  Keypair,
  Networks,
  hash,
  nativeToScVal,
  rpc as stellarRpc,
  xdr,
} from "@stellar/stellar-sdk";
import { NextRequest, NextResponse } from "next/server";

import { Client as SacClient } from "@/lib/sac";
import { basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { PasskeyKit } from "passkey-kit";

export async function POST(request: NextRequest) {
  try {
    const server = new Server(RPC_URL, {
      allowHttp: true,
    });
    console.log("✅ Server connection established");

    console.log("📊 Fetching source account from server");
    const sourceAccount = await server.getAccount(TREASURY_WALLET.publicKey());
    console.log(sourceAccount);
    console.log(
      `✅ Source account fetched. Sequence: ${sourceAccount.sequenceNumber()}`
    );

    const TRANSFER_AMOUNT = 5 * 10_000_000;
    console.log(`💰 Transfer amount: ${TRANSFER_AMOUNT}`);

    console.log("🔨 Building transaction");
    const sacClient = new SacClient({
      contractId: XMUSD_CONTRACT_ADDRESS,
      networkPassphrase: Networks.TESTNET,
      rpcUrl: RPC_URL,
    });
    const tx = await sacClient.transfer({
      from: SWC_ADDRESS,
      to: TREASURY_WALLET.publicKey(),
      amount: BigInt(TRANSFER_AMOUNT),
    });

    const passkeyKit = new PasskeyKit({
      networkPassphrase: Networks.TESTNET,
      rpcUrl: RPC_URL,
      walletWasmHash: SWC_WASM_HASH,
    });
    passkeyKit.wallet = {
      options: {},
      contractId: XMUSD_CONTRACT_ADDRESS,
    } as any;
    const signedTx = await passkeyKit.sign(tx, {
      keypair: SIGNER_1_WALLET,
    });
    const sentTxM = await signedTx.send();

    // await tx.signAuthEntries({
    //   address: TREASURY_WALLET.publicKey(),
    //   signAuthEntry: TREASURY_WALLET.signAuthEntry,
    // });
    // feeBump.sign(TREASURY_WALLET);
    // const simulation = await tx.simulation;
    return NextResponse.json(
      {
        sentTxM,
      },
      { status: 200 }
    );

    const sentTx = await server.sendTransaction(innerPreparedTx);
    if (sentTx.status === "ERROR") {
      console.error(JSON.stringify(sentTx, null, 2));
      throw new Error("Failed to send transaction");
    }
    console.log(`Sent tx: ${JSON.stringify(sentTx)}`);
    const finalTx = await waitForTx(server, sentTx.hash);

    return NextResponse.json(
      {
        success: true,
        message: `Transaction success!`,
        status: finalTx.status,
        txHash: finalTx.txHash,
        from: TREASURY_WALLET.publicKey(),
        to: SWC_ADDRESS,
        amount: TRANSFER_AMOUNT,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      {
        success: false,
        error: error,
      },
      { status: 500 }
    );
  }
}
