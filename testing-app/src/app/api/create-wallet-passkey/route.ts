import { RPC_URL } from "@/lib/const";
import {
  PASSKEY_WASM_HASH,
  SIGNER_1_WALLET,
  SWC_WASM_HASH,
  TREASURY_WALLET,
} from "@/lib/wallets";
import {
  basicNodeSigner,
  Client,
  Option,
  u32,
} from "@stellar/stellar-sdk/contract";
import { Networks } from "@stellar/stellar-sdk";
import { NextRequest, NextResponse } from "next/server";
export type SignerExpiration = readonly [Option<u32>];
export type SignerLimits = readonly [
  Option<Map<string, Option<Array<SignerKey>>>>
];
export type SignerStorage =
  | { tag: "Persistent"; values: void }
  | { tag: "Temporary"; values: void };
export type Signer =
  | {
      tag: "Policy";
      values: readonly [string, SignerExpiration, SignerLimits, SignerStorage];
    }
  | {
      tag: "Ed25519";
      values: readonly [Buffer, SignerExpiration, SignerLimits, SignerStorage];
    }
  | {
      tag: "Secp256r1";
      values: readonly [
        Buffer,
        Buffer,
        SignerExpiration,
        SignerLimits,
        SignerStorage
      ];
    };
export type SignerKey =
  | { tag: "Policy"; values: readonly [string] }
  | { tag: "Ed25519"; values: readonly [Buffer] }
  | { tag: "Secp256r1"; values: readonly [Buffer] };
export type SignerVal =
  | { tag: "Policy"; values: readonly [SignerExpiration, SignerLimits] }
  | { tag: "Ed25519"; values: readonly [SignerExpiration, SignerLimits] }
  | {
      tag: "Secp256r1";
      values: readonly [Buffer, SignerExpiration, SignerLimits];
    };

export async function POST(request: NextRequest) {
  try {
    const signer: Signer = {
      tag: "Ed25519",
      values: [
        SIGNER_1_WALLET.rawPublicKey(),
        [undefined],
        [undefined],
        { tag: "Persistent", values: undefined },
      ],
    };
    const deploymentTx = await Client.deploy(
      {
        signer,
      },
      {
        rpcUrl: RPC_URL,
        wasmHash: PASSKEY_WASM_HASH,
        networkPassphrase: Networks.TESTNET,
        publicKey: TREASURY_WALLET.publicKey(),
        timeoutInSeconds: 45,
      }
    );
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
