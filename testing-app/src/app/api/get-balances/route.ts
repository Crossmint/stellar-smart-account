import { RPC_URL, XM_USD_ASSET } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import {
  SWC_ADDRESS,
  TREASURY_WALLET,
  XLM_TESTNET_ADDRESS,
} from "@/lib/wallets";
import { XMUSD_CONTRACT_ADDRESS } from "@/lib/wallets";
import {
  Asset,
  BASE_FEE,
  Contract,
  nativeToScVal,
  Networks,
  Operation,
  TransactionBuilder,
  Horizon,
} from "@stellar/stellar-sdk";
import { NextRequest, NextResponse } from "next/server";
import { Server } from "@stellar/stellar-sdk/rpc";

const ASSETS = [
  {
    address: XLM_TESTNET_ADDRESS,
    asset: "XLM",
  },
  {
    address: XMUSD_CONTRACT_ADDRESS,
    asset: "USDXM",
  },
];

async function getBalances() {
  const horizonServer = new Horizon.Server(
    "https://horizon-testnet.stellar.org"
  );
  //   const server = new Server(RPC_URL);
  //   const contract = new Contract(XMUSD_CONTRACT_ADDRESS);

  const { balances } = await horizonServer
    .accounts()
    .accountId(TREASURY_WALLET.publicKey())
    .call();
  console.log(balances);
  return balances;
}

export async function POST(request: NextRequest) {
  try {
    const balances = await getBalances();

    return NextResponse.json(
      {
        success: true,
        message: `Fetch balances success!`,
        balances,
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
