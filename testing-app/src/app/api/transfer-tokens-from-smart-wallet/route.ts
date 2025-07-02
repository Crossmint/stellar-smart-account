import { RPC_URL } from "@/lib/const";
import { waitForTx } from "@/lib/txs";
import {
  PASSKEY_SWC_ADDRESS,
  PASSKEY_WASM_HASH,
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

import { basicNodeSigner } from "@stellar/stellar-sdk/contract";
import {
  PasskeyKit,
  PasskeyServer,
  SACClient,
  PasskeyClient,
} from "passkey-kit";

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

    const TRANSFER_AMOUNT = 0.01 * 10_000_000;
    console.log(`💰 Transfer amount: ${TRANSFER_AMOUNT}`);

    console.log("🔨 Building transaction");
    const sacClientStatic = new SACClient({
      networkPassphrase: Networks.TESTNET,
      rpcUrl: RPC_URL,
    });
    const sacClient = sacClientStatic.getSACClient(XLM_TESTNET_ADDRESS);
    const tx = await sacClient.transfer({
      from: PASSKEY_SWC_ADDRESS,
      to: TREASURY_WALLET.publicKey(),
      amount: BigInt(TRANSFER_AMOUNT),
    });

    const passkeyKit = new PasskeyKit({
      networkPassphrase: Networks.TESTNET,
      rpcUrl: RPC_URL,
      walletWasmHash: PASSKEY_WASM_HASH,
    });
    passkeyKit.wallet = new PasskeyClient({
      networkPassphrase: Networks.TESTNET,
      rpcUrl: RPC_URL,
      contractId: PASSKEY_SWC_ADDRESS,
    });
    let signedTx = await passkeyKit.sign(tx, {
      keypair: SIGNER_1_WALLET,
    });
    await tx.simulate();
    // console.log(tx.simulation);
    // return NextResponse.json(
    //   {
    //     simulation: tx.simulation,
    //   },
    //   { status: 200 }
    // );

    console.log("Tx has been signed");
    const data = new FormData();

    console.log("1");
    const txn = signedTx.built!.toXDR();

    console.log("2");
    data.set("xdr", txn);

    console.log("3");
    const res = await fetch("https://testnet.launchtube.xyz", {
      method: "POST",
      headers: {
        "X-Client-Name": "passkey-kit",
        "X-Client-Version": "0.0.1",
        Authorization: `Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIzMjU3YTQ3ZTEwOWQ5ZThmNzkzNDM5ZTI2YWUzYjc5MWY3ZTU5YWU5NjkyY2E1YjdhMzg2NjRhYTc3ODlhY2FkIiwiZXhwIjoxNzU4NzM5MDI5LCJjcmVkaXRzIjoxMDAwMDAwMDAwLCJpYXQiOjE3NTE0ODE0Mjl9.SZ6NWypEnFL-jTOnyDfTN8NpAvJYNezXpzR894e-YCc`,
      },
      body: data,
    });
    const json = await res.json();
    console.log(json);
    // const server2 = new PasskeyServer({
    //   rpcUrl: RPC_URL,
    //   launchtubeUrl: "https://testnet.launchtube.xyz",
    // });
    // const sentTxM = await server2.send(signedTx);
    return NextResponse.json(
      {
        json,
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

// Function to recursively filter out unchanged values
function filterUnchangedValues(diff: any): any {
  if (diff && typeof diff === "object" && diff.type) {
    // If it's a leaf node with type, only return if not unchanged
    if (diff.type === deepDiffMapper.VALUE_UNCHANGED) {
      return undefined;
    }
    return diff;
  }

  if (diff && typeof diff === "object" && !Array.isArray(diff)) {
    // If it's an object, recursively filter its properties
    const filtered: any = {};
    let hasChanges = false;

    for (const key in diff) {
      const filteredValue = filterUnchangedValues(diff[key]);
      if (filteredValue !== undefined) {
        filtered[key] = filteredValue;
        hasChanges = true;
      }
    }

    return hasChanges ? filtered : undefined;
  }

  if (diff && typeof diff === "object" && Array.isArray(diff)) {
    return diff.map(filterUnchangedValues);
  }

  return diff;
}

var deepDiffMapper = (function () {
  return {
    VALUE_CREATED: "created",
    VALUE_UPDATED: "updated",
    VALUE_DELETED: "deleted",
    VALUE_UNCHANGED: "unchanged",
    map: function (obj1: any, obj2: any) {
      if (this.isFunction(obj1) || this.isFunction(obj2)) {
        throw "Invalid argument. Function given, object expected.";
      }
      if (this.isValue(obj1) || this.isValue(obj2)) {
        return {
          type: this.compareValues(obj1, obj2),
          data: obj1 === undefined ? obj2 : obj1,
        };
      }

      var diff: any = {};
      for (var key in obj1) {
        if (this.isFunction(obj1[key])) {
          continue;
        }

        var value2 = undefined;
        if (obj2[key] !== undefined) {
          value2 = obj2[key];
        }

        diff[key] = this.map(obj1[key], value2);
      }
      for (var key in obj2) {
        if (this.isFunction(obj2[key]) || diff[key] !== undefined) {
          continue;
        }

        diff[key] = this.map(undefined, obj2[key]);
      }

      return diff;
    },
    compareValues: function (value1: any, value2: any) {
      if (value1 === value2) {
        return this.VALUE_UNCHANGED;
      }
      if (
        this.isDate(value1) &&
        this.isDate(value2) &&
        value1.getTime() === value2.getTime()
      ) {
        return this.VALUE_UNCHANGED;
      }
      if (value1 === undefined) {
        return this.VALUE_CREATED;
      }
      if (value2 === undefined) {
        return this.VALUE_DELETED;
      }
      return this.VALUE_UPDATED;
    },
    isFunction: function (x: any) {
      return Object.prototype.toString.call(x) === "[object Function]";
    },
    isArray: function (x: any) {
      return Object.prototype.toString.call(x) === "[object Array]";
    },
    isDate: function (x: any) {
      return Object.prototype.toString.call(x) === "[object Date]";
    },
    isObject: function (x: any) {
      return Object.prototype.toString.call(x) === "[object Object]";
    },
    isValue: function (x: any) {
      return !this.isObject(x) && !this.isArray(x);
    },
  };
})();
