import { Buffer } from "buffer";
import { Address } from '@stellar/stellar-sdk';
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from '@stellar/stellar-sdk/contract';
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Typepoint,
  Duration,
} from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk'
export * as contract from '@stellar/stellar-sdk/contract'
export * as rpc from '@stellar/stellar-sdk/rpc'

if (typeof window !== 'undefined') {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}




export const Errors = {
  0: {message:"NoSigners"},
  1: {message:"NotFound"},
  2: {message:"MatchingSignatureNotFound"},
  3: {message:"SignatureVerificationFailed"},
  4: {message:"SignerExpired"},
  5: {message:"SignerAlreadyExists"},
  6: {message:"SignerNotFound"},
  7: {message:"AlreadyInitialized"},
  8: {message:"NotInitialized"},
  9: {message:"StorageEntryNotFound"},
  10: {message:"StorageEntryAlreadyExists"}
}

export const Errors = {
  0: {message:"AlreadyInitialized"},
  1: {message:"NotInitialized"}
}

export interface Client {
  /**
   * Construct and simulate a add_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_signer: ({signer}: {signer: Signer}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a update_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  update_signer: ({signer}: {signer: Signer}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a revoke_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  revoke_signer: ({signer_key}: {signer_key: SignerKey}, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Result<void>>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {signers}: {signers: Array<Signer>},
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy({signers}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAACwAAAAAAAAAJTm9TaWduZXJzAAAAAAAAAAAAAAAAAAAITm90Rm91bmQAAAABAAAAAAAAABlNYXRjaGluZ1NpZ25hdHVyZU5vdEZvdW5kAAAAAAAAAgAAAAAAAAAbU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkAAAAAAMAAAAAAAAADVNpZ25lckV4cGlyZWQAAAAAAAAEAAAAAAAAABNTaWduZXJBbHJlYWR5RXhpc3RzAAAAAAUAAAAAAAAADlNpZ25lck5vdEZvdW5kAAAAAAAGAAAAAAAAABJBbHJlYWR5SW5pdGlhbGl6ZWQAAAAAAAcAAAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAAIAAAAAAAAABRTdG9yYWdlRW50cnlOb3RGb3VuZAAAAAkAAAAAAAAAGVN0b3JhZ2VFbnRyeUFscmVhZHlFeGlzdHMAAAAAAAAK",
        "AAAAAAAAAAAAAAANX19jb25zdHJ1Y3RvcgAAAAAAAAEAAAAAAAAAB3NpZ25lcnMAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAA",
        "AAAAAAAAAAAAAAAKYWRkX3NpZ25lcgAAAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAANdXBkYXRlX3NpZ25lcgAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAANcmV2b2tlX3NpZ25lcgAAAAAAAAEAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAAKc2lnbmF0dXJlcwAAAAAH0AAAAApTaWduYXR1cmVzAAAAAAAAAAAADWF1dGhfY29udGV4dHMAAAAAAAPqAAAH0AAAAAdDb250ZXh0AAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAAgAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAAAAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAQ==" ]),
      options
    )
  }
  public readonly fromJSON = {
    add_signer: this.txFromJSON<Result<void>>,
        update_signer: this.txFromJSON<Result<void>>,
        revoke_signer: this.txFromJSON<Result<void>>
  }
}