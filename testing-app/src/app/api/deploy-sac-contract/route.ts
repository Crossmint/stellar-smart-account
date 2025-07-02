import { RPC_URL, XM_USD_ASSET } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import {
  SWC_ADDRESS,
  TREASURY_WALLET,
  TREASURY_WALLET_2,
  USDXM_DISTRIBUTOR_WALLET,
  USDXM_ISSUER_WALLET,
  XLM_TESTNET_ADDRESS,
  XMUSD_CONTRACT_ADDRESS,
} from "@/lib/wallets";
import { Server } from "@stellar/stellar-sdk/rpc";
import { NextRequest, NextResponse } from "next/server";
import {
  Asset,
  BASE_FEE,
  Networks,
  Operation,
  TransactionBuilder,
  Horizon,
  Contract,
  Account,
  Address,
  nativeToScVal,
} from "@stellar/stellar-sdk";

export async function POST(request: NextRequest) {
  try {
    const server = new Horizon.Server("https://horizon-testnet.stellar.org", {
      allowHttp: true,
    });
    console.log("✅ Server connection established");

    console.log("📊 Fetching source account from server");
    const issuerAccount = await server.loadAccount(
      USDXM_ISSUER_WALLET.publicKey()
    );
    console.log(issuerAccount);
    console.log(
      `✅ Source account fetched. Sequence: ${issuerAccount.sequenceNumber()}`
    );

    const TRANSFER_AMOUNT = 0.5 * 1_000_000;
    console.log(`💰 Transfer amount: ${TRANSFER_AMOUNT}`);

    // console.log("🔨 Building transaction");
    // const tx = new TransactionBuilder(issuerAccount, {
    //   fee: (Number(BASE_FEE) * 5).toString(),
    //   networkPassphrase: Networks.TESTNET,
    // })
    //   .addOperation(
    //     Operation.changeTrust({
    //       asset: XM_USD_ASSET,
    //     })
    //   )
    //   //   .addOperation(
    //   //     Operation.payment({
    //   //       destination: TREASURY_WALLET.publicKey(),
    //   //       asset: XM_USD_ASSET,
    //   //       amount: "10000000000",
    //   //     })
    //   //   )
    //   .setTimeout(30)
    //   .setNetworkPassphrase(Networks.TESTNET)
    //   .build();

    // tx.sign(USDXM_ISSUER_WALLET);
    // const sentTx = await server.submitTransaction(tx);
    // console.log(sentTx);
    // console.log("🔨 Building transaction");
    // const treasuryAccount = await server.loadAccount(
    //   USDXM_DISTRIBUTOR_WALLET.publicKey()
    // );
    // const tx = new TransactionBuilder(treasuryAccount, {
    //   fee: (Number(BASE_FEE) * 5).toString(),
    //   networkPassphrase: Networks.TESTNET,
    // })
    //   .addOperation(
    //     Operation.payment({
    //       destination: USDXM_DISTRIBUTOR_WALLET.publicKey(),
    //       asset: XM_USD_ASSET,
    //       amount: "10000000000",
    //     })
    //   )
    //   .setTimeout(30)
    //   .setNetworkPassphrase(Networks.TESTNET)
    //   .build();

    // tx.sign(USDXM_DISTRIBUTOR_WALLET);
    // const sentTx = await server.submitTransaction(tx);
    // console.log(sentTx);
    // return NextResponse.json(
    //   {
    //     success: true,
    //     message: `Transaction success!`,
    //   },
    //   { status: 200 }
    // );

    const serverSoroban = new Server(RPC_URL);
    const contract = new Contract(XMUSD_CONTRACT_ADDRESS);
    const account = await serverSoroban.getAccount(
      USDXM_ISSUER_WALLET.publicKey()
    );
    const fromSc = nativeToScVal(USDXM_ISSUER_WALLET.publicKey(), {
      type: "address",
    });
    const toSc = nativeToScVal(TREASURY_WALLET.publicKey(), {
      type: "address",
    });
    const amtSc = nativeToScVal(100000000000, { type: "i128" });
    const tx2 = new TransactionBuilder(account, {
      fee: (Number(BASE_FEE) * 5).toString(),
      networkPassphrase: Networks.TESTNET,
    })
      .addOperation(
        Operation.invokeContractFunction({
          contract: XMUSD_CONTRACT_ADDRESS,
          function: "transfer",
          args: [fromSc, toSc, amtSc],
        })
      )
      .setTimeout(30)
      .setNetworkPassphrase(Networks.TESTNET)
      .build();

    const preped2 = await serverSoroban.prepareTransaction(tx2);
    preped2.sign(USDXM_ISSUER_WALLET);
    const sentTx2 = await serverSoroban.sendTransaction(preped2);
    await waitForTx(serverSoroban, sentTx2.hash);
    console.log(sentTx2);

    // if (!scAddress) {
    //   throw new Error("Failed to deploy SAC");
    // }
    // const contractId = Address.fromScAddress(scAddress).toString();

    return NextResponse.json(
      {
        success: true,
        message: `Transaction success!`,
        txHash: sentTx2.hash,
        sacContractAddress: "??",
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
