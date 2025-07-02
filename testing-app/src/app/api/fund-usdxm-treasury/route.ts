import { RPC_URL, XM_USD_ASSET } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import { SWC_ADDRESS, TREASURY_WALLET } from "@/lib/wallets";
import { XMUSD_CONTRACT_ADDRESS } from "@/lib/wallets";
import {
  Asset,
  BASE_FEE,
  Contract,
  nativeToScVal,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { NextRequest, NextResponse } from "next/server";
import { Server } from "@stellar/stellar-sdk/rpc";

async function mintToTreasuryWallet(rawAmount: bigint) {
  // contract:CBZFQBLLULOAUWLJGUKUZUXVOSTBOLIQS4TPUGLXXDZHIV5XX5VEZATL, topics:[error, Error(Value, InvalidInput)], data:["symbol not found in slice of strs", xfer]
  const server = new Server(RPC_URL);
  const networkPassphrase = Networks.TESTNET;
  const issuerKp = TREASURY_WALLET;
  const issuerPk = issuerKp.publicKey();
  const issuerAcct = await server.getAccount(issuerPk);

  const contract = new Contract(XMUSD_CONTRACT_ADDRESS);
  //   console.log(contract.getFootprint());

  const fromSc = nativeToScVal(issuerPk, { type: "address" });
  const toSc = nativeToScVal(issuerPk, { type: "address" });
  const amtSc = nativeToScVal(rawAmount, { type: "i128" });

  const tx = new TransactionBuilder(issuerAcct, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call("transfer", fromSc, toSc, amtSc))
    // .addOperation(
    //   Operation.changeTrust({
    //     asset: XM_USD_ASSET,
    //   })
    // )
    // .addOperation(
    //   Operation.payment({
    //     destination: issuerPk,
    //     asset: XM_USD_ASSET,
    //     amount: "1000",
    //     source: issuerPk,
    //   })
    // )
    .setTimeout(30)
    .build();

  const prepped = await server.prepareTransaction(tx);
  prepped.sign(issuerKp);
  const result = await server.sendTransaction(prepped);
  console.log("Mint successful, transaction hash:", result.hash);
  return waitForTx(server, result.hash);
}

export async function POST(request: NextRequest) {
  try {
    const transferAmount = BigInt(1000_0_000_000); // 1,000 tokens with 7 decimals
    const tx = await mintToTreasuryWallet(transferAmount).catch(console.error);
    if (!tx) {
      throw new Error("Failed to mint tokens");
    }

    return NextResponse.json(
      {
        success: true,
        message: `Transaction success!`,
        status: tx.status,
        txHash: tx.txHash,
        to: TREASURY_WALLET.publicKey(),
        amount: transferAmount.toString(),
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
