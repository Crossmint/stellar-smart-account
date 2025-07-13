import { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import { Address, Transaction, xdr } from "factory";

/**
 * 🎨 Pretty print authorization entries for smart wallet transactions
 * Displays signer info, authorization contexts, and transaction details in a cool format
 */
export function printAuthEntries(tx: AssembledTransaction<unknown>) {
  if (tx.simulation == null) {
    console.log("❌ No simulation data available");
    return;
  }

  const authEntries = tx.simulationData.result.auth;

  if (!authEntries || authEntries.length === 0) {
    console.log("ℹ️  No authorization entries found");
    return;
  }

  console.log("\n🔐 Authorization Entries Analysis");
  console.log("=".repeat(50));

  authEntries.forEach((authEntry, index) => {
    console.log(`\n📋 Entry ${index + 1}:`);
    console.log("-".repeat(30));

    const credentials = xdr.SorobanCredentials.fromXDR(
      authEntry.credentials().toXDR()
    );

    const credentialType = credentials.switch().name;
    console.log(`🔑 Credential Type: ${credentialType}`);

    if (credentials.address) {
      const address = Address.fromScAddress(
        credentials.address().address()
      ).toString();
      console.log(`🏠 Address: ${address}`);
    }

    // Add more details about the auth entry
    console.log(`📊 Auth Entry Details:`);
    console.log(
      `   - Root Invocation Function: ${authEntry
        .rootInvocation()
        .function()
        .contractFn()
        .functionName()}`
    );

    if (authEntry.rootInvocation().subInvocations().length > 0) {
      console.log(
        `   - Sub-invocations: ${
          authEntry.rootInvocation().subInvocations().length
        }`
      );
    }
  });

  console.log("\n" + "=".repeat(50));
  console.log(
    `✅ Total authorization entries processed: ${authEntries.length}\n`
  );
}
