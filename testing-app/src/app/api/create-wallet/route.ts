import { RPC_URL } from "@/lib/const";
import { SWC_WASM_HASH, TREASURY_WALLET } from "@/lib/wallets";
import { basicNodeSigner, Client } from "@stellar/stellar-sdk/contract";
import { NextRequest, NextResponse } from "next/server";
import { Networks } from "stellar-sdk";

export async function POST(request: NextRequest) {
  try {
    const deploymentTx = await Client.deploy(null, {
      rpcUrl: RPC_URL,
      wasmHash: SWC_WASM_HASH,
      networkPassphrase: Networks.TESTNET,
      publicKey: TREASURY_WALLET.publicKey(),
      timeoutInSeconds: 45,
    });
    const sentTx = await deploymentTx.signAndSend({
      signTransaction: basicNodeSigner(TREASURY_WALLET, Networks.TESTNET)
        .signTransaction,
    });
    console.log(sentTx);
    const result = sentTx.result;
    console.log(`Result: ${result}`);
    return NextResponse.json(
      {
        success: true,
        sentTx,
        message: `Contract was deployed to address: {}`,
      },
      { status: 200 }
    );
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: "Failed to create wallet",
      },
      { status: 500 }
    );
  }
}
