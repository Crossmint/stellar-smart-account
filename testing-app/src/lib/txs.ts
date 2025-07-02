import { Server } from "@stellar/stellar-sdk/rpc";

export async function waitForTx(server: Server, txHash: string) {
  console.log(`Fetching tx ${txHash}`);
  const tx = await server.getTransaction(txHash);
  /*
        SUCCESS = "SUCCESS",
        NOT_FOUND = "NOT_FOUND",
        FAILED = "FAILED"
  */
  console.log(`Tx status: ${tx.status}`);
  if (tx.status === "NOT_FOUND") {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return waitForTx(server, txHash);
  }
  if (tx.status === "FAILED") {
    throw new Error("Transaction failed");
  }
  if (tx.status === "SUCCESS") {
    return tx;
  }
  throw new Error("Transaction status not found");
}
