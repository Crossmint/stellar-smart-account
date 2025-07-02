import { RPC_URL } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import {
  SWC_ADDRESS,
  TREASURY_WALLET,
  XLM_TESTNET_ADDRESS,
  XMUSD_CONTRACT_ADDRESS,
} from "@/lib/wallets";
import { Server } from "@stellar/stellar-sdk/rpc";
import { NextRequest, NextResponse } from "next/server";
import {
  Address,
  BASE_FEE,
  Networks,
  Operation,
  ScInt,
  TransactionBuilder,
} from "stellar-sdk";

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
    const tx = new TransactionBuilder(sourceAccount, {
      fee: (Number(BASE_FEE) * 5).toString(),
      networkPassphrase: Networks.TESTNET,
    })
      .addOperation(
        Operation.invokeContractFunction({
          contract: XMUSD_CONTRACT_ADDRESS,
          function: "transfer",
          args: [
            new Address(TREASURY_WALLET.publicKey()).toScVal(),
            new Address(SWC_ADDRESS).toScVal(),
            new ScInt(TRANSFER_AMOUNT, { type: "i128" }).toScVal(),
          ],
        })
      )
      .setTimeout(30)
      .setNetworkPassphrase(Networks.TESTNET)
      .build();

    const preparedTx = await server.prepareTransaction(tx);
    preparedTx.sign(TREASURY_WALLET);
    const sentTx = await server.sendTransaction(preparedTx);
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
