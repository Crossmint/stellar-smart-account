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




export type SignerPolicy = {tag: "TimeBased", values: readonly [TimeBasedPolicy]} | {tag: "ContractDenyList", values: readonly [ContractDenyListPolicy]} | {tag: "ContractAllowList", values: readonly [ContractAllowListPolicy]};

export type SignerRole = {tag: "Admin", values: void} | {tag: "Standard", values: void} | {tag: "Restricted", values: readonly [Array<SignerPolicy>]};


export interface ContractAllowListPolicy {
  allowed_contracts: Array<string>;
}


export interface ContractDenyListPolicy {
  denied_contracts: Array<string>;
}


export interface TimeBasedPolicy {
  not_after: u64;
  not_before: u64;
}

export type SignerProof = {tag: "Ed25519", values: readonly [Buffer]};

export type AuthorizationPayloads = readonly [Map<SignerKey, SignerProof>];

export type SignerKey = {tag: "Ed25519", values: readonly [Buffer]};

export type Signer = {tag: "Ed25519", values: readonly [Ed25519Signer, SignerRole]};


/**
 * Ed25519 signer implementation
 */
export interface Ed25519Signer {
  public_key: Buffer;
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
  10: {message:"StorageEntryAlreadyExists"},
  11: {message:"InvalidProofType"},
  12: {message:"NoProofsInAuthEntry"},
  13: {message:"InsufficientPermissions"},
  14: {message:"InsufficientPermissionsOnCreation"},
  15: {message:"InvalidPolicy"},
  16: {message:"InvalidTimeRange"},
  17: {message:"InvalidNotAfterTime"}
}

export type StorageType = {tag: "Persistent", values: void} | {tag: "Instance", values: void};

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
      new ContractSpec([ "AAAAAgAAAAAAAAAAAAAADFNpZ25lclBvbGljeQAAAAMAAAABAAAAAAAAAAlUaW1lQmFzZWQAAAAAAAABAAAH0AAAAA9UaW1lQmFzZWRQb2xpY3kAAAAAAQAAAAAAAAAQQ29udHJhY3REZW55TGlzdAAAAAEAAAfQAAAAFkNvbnRyYWN0RGVueUxpc3RQb2xpY3kAAAAAAAEAAAAAAAAAEUNvbnRyYWN0QWxsb3dMaXN0AAAAAAAAAQAAB9AAAAAXQ29udHJhY3RBbGxvd0xpc3RQb2xpY3kA",
        "AAAAAgAAAAAAAAAAAAAAClNpZ25lclJvbGUAAAAAAAMAAAAAAAAAAAAAAAVBZG1pbgAAAAAAAAAAAAAAAAAACFN0YW5kYXJkAAAAAQAAAAAAAAAKUmVzdHJpY3RlZAAAAAAAAQAAA+oAAAfQAAAADFNpZ25lclBvbGljeQ==",
        "AAAAAQAAAAAAAAAAAAAAF0NvbnRyYWN0QWxsb3dMaXN0UG9saWN5AAAAAAEAAAAAAAAAEWFsbG93ZWRfY29udHJhY3RzAAAAAAAD6gAAABM=",
        "AAAAAQAAAAAAAAAAAAAAFkNvbnRyYWN0RGVueUxpc3RQb2xpY3kAAAAAAAEAAAAAAAAAEGRlbmllZF9jb250cmFjdHMAAAPqAAAAEw==",
        "AAAAAQAAAAAAAAAAAAAAD1RpbWVCYXNlZFBvbGljeQAAAAACAAAAAAAAAAlub3RfYWZ0ZXIAAAAAAAAGAAAAAAAAAApub3RfYmVmb3JlAAAAAAAG",
        "AAAAAgAAAAAAAAAAAAAAC1NpZ25lclByb29mAAAAAAEAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAQA==",
        "AAAAAQAAAAAAAAAAAAAAFUF1dGhvcml6YXRpb25QYXlsb2FkcwAAAAAAAAEAAAAAAAAAATAAAAAAAAPsAAAH0AAAAAlTaWduZXJLZXkAAAAAAAfQAAAAC1NpZ25lclByb29mAA==",
        "AAAAAgAAAAAAAAAAAAAACVNpZ25lcktleQAAAAAAAAEAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAIA==",
        "AAAAAgAAAAAAAAAAAAAABlNpZ25lcgAAAAAAAQAAAAEAAAAAAAAAB0VkMjU1MTkAAAAAAgAAB9AAAAANRWQyNTUxOVNpZ25lcgAAAAAAB9AAAAAKU2lnbmVyUm9sZQAA",
        "AAAAAQAAAB1FZDI1NTE5IHNpZ25lciBpbXBsZW1lbnRhdGlvbgAAAAAAAAAAAAANRWQyNTUxOVNpZ25lcgAAAAAAAAEAAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAAAg",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAEgAAAAAAAAAJTm9TaWduZXJzAAAAAAAAAAAAAAAAAAAITm90Rm91bmQAAAABAAAAAAAAABlNYXRjaGluZ1NpZ25hdHVyZU5vdEZvdW5kAAAAAAAAAgAAAAAAAAAbU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkAAAAAAMAAAAAAAAADVNpZ25lckV4cGlyZWQAAAAAAAAEAAAAAAAAABNTaWduZXJBbHJlYWR5RXhpc3RzAAAAAAUAAAAAAAAADlNpZ25lck5vdEZvdW5kAAAAAAAGAAAAAAAAABJBbHJlYWR5SW5pdGlhbGl6ZWQAAAAAAAcAAAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAAIAAAAAAAAABRTdG9yYWdlRW50cnlOb3RGb3VuZAAAAAkAAAAAAAAAGVN0b3JhZ2VFbnRyeUFscmVhZHlFeGlzdHMAAAAAAAAKAAAAAAAAABBJbnZhbGlkUHJvb2ZUeXBlAAAACwAAAAAAAAATTm9Qcm9vZnNJbkF1dGhFbnRyeQAAAAAMAAAAAAAAABdJbnN1ZmZpY2llbnRQZXJtaXNzaW9ucwAAAAANAAAAAAAAACFJbnN1ZmZpY2llbnRQZXJtaXNzaW9uc09uQ3JlYXRpb24AAAAAAAAOAAAAAAAAAA1JbnZhbGlkUG9saWN5AAAAAAAADwAAAAAAAAAQSW52YWxpZFRpbWVSYW5nZQAAABAAAAAAAAAAE0ludmFsaWROb3RBZnRlclRpbWUAAAAAEQ==",
        "AAAAAAAAAAAAAAANX19jb25zdHJ1Y3RvcgAAAAAAAAEAAAAAAAAAB3NpZ25lcnMAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAA",
        "AAAAAAAAAAAAAAAKYWRkX3NpZ25lcgAAAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAANdXBkYXRlX3NpZ25lcgAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAANcmV2b2tlX3NpZ25lcgAAAAAAAAEAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAp1DdXN0b20gYXV0aG9yaXphdGlvbiBmdW5jdGlvbiBpbnZva2VkIGJ5IHRoZSBTb3JvYmFuIHJ1bnRpbWUuCgpUaGlzIGZ1bmN0aW9uIGltcGxlbWVudHMgdGhlIHdhbGxldCdzIGF1dGhvcml6YXRpb24gbG9naWM6CjEuIFZlcmlmaWVzIHRoYXQgYWxsIHByb3ZpZGVkIHNpZ25hdHVyZXMgYXJlIGNyeXB0b2dyYXBoaWNhbGx5IHZhbGlkCjIuIENoZWNrcyB0aGF0IGF0IGxlYXN0IG9uZSBhdXRob3JpemVkIHNpZ25lciBoYXMgYXBwcm92ZWQgZWFjaCBvcGVyYXRpb24KMy4gRW5zdXJlcyBzaWduZXJzIGhhdmUgdGhlIHJlcXVpcmVkIHBlcm1pc3Npb25zIGZvciB0aGUgcmVxdWVzdGVkIG9wZXJhdGlvbnMKCiMgQXJndW1lbnRzCiogYGVudmAgLSBUaGUgY29udHJhY3QgZW52aXJvbm1lbnQKKiBgc2lnbmF0dXJlX3BheWxvYWRgIC0gSGFzaCBvZiB0aGUgZGF0YSB0aGF0IHdhcyBzaWduZWQKKiBgYXV0aF9wYXlsb2Fkc2AgLSBNYXAgb2Ygc2lnbmVyIGtleXMgdG8gdGhlaXIgc2lnbmF0dXJlIHByb29mcwoqIGBhdXRoX2NvbnRleHRzYCAtIExpc3Qgb2Ygb3BlcmF0aW9ucyBiZWluZyBhdXRob3JpemVkCgojIFJldHVybnMKKiBgT2soKCkpYCBpZiBhdXRob3JpemF0aW9uIHN1Y2NlZWRzCiogYEVycihFcnJvcilgIGlmIGF1dGhvcml6YXRpb24gZmFpbHMgZm9yIGFueSByZWFzb24AAAAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAANYXV0aF9wYXlsb2FkcwAAAAAAB9AAAAAVQXV0aG9yaXphdGlvblBheWxvYWRzAAAAAAAAAAAAAA1hdXRoX2NvbnRleHRzAAAAAAAD6gAAB9AAAAAHQ29udGV4dAAAAAABAAAD6QAAA+0AAAAAAAAAAw==",
        "AAAAAgAAAAAAAAAAAAAAC1N0b3JhZ2VUeXBlAAAAAAIAAAAAAAAAAAAAAApQZXJzaXN0ZW50AAAAAAAAAAAAAAAAAAhJbnN0YW5jZQ==" ]),
      options
    )
  }
  public readonly fromJSON = {
    add_signer: this.txFromJSON<Result<void>>,
        update_signer: this.txFromJSON<Result<void>>,
        revoke_signer: this.txFromJSON<Result<void>>
  }
}