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

export type SignatureProofs = readonly [Map<SignerKey, SignerProof>];

export type SignerKey = {tag: "Ed25519", values: readonly [Buffer]};

export type Signer = {tag: "Ed25519", values: readonly [Ed25519Signer, SignerRole]};


/**
 * Ed25519 signer implementation
 */
export interface Ed25519Signer {
  public_key: Buffer;
}

export const Errors = {
  /**
   * Contract has already been initialized
   */
  0: {message:"AlreadyInitialized"},
  /**
   * Contract has not been initialized yet
   */
  1: {message:"NotInitialized"},
  /**
   * Storage entry was not found
   */
  10: {message:"StorageEntryNotFound"},
  /**
   * Storage entry already exists
   */
  11: {message:"StorageEntryAlreadyExists"},
  /**
   * No signers are configured for the wallet
   */
  20: {message:"NoSigners"},
  /**
   * Signer already exists in the wallet
   */
  21: {message:"SignerAlreadyExists"},
  /**
   * Signer was not found in the wallet
   */
  22: {message:"SignerNotFound"},
  /**
   * Signer has expired and is no longer valid
   */
  23: {message:"SignerExpired"},
  24: {message:"CannotRevokeAdminSigner"},
  /**
   * No matching signature found for the given criteria
   */
  40: {message:"MatchingSignatureNotFound"},
  /**
   * Signature verification failed during authentication
   */
  41: {message:"SignatureVerificationFailed"},
  /**
   * Invalid proof type provided
   */
  42: {message:"InvalidProofType"},
  /**
   * No proofs found in the authentication entry
   */
  43: {message:"NoProofsInAuthEntry"},
  /**
   * Insufficient permissions to perform the requested operation
   */
  60: {message:"InsufficientPermissions"},
  /**
   * Insufficient permissions during wallet creation
   */
  61: {message:"InsufficientPermissionsOnCreation"},
  /**
   * Invalid policy configuration
   */
  80: {message:"InvalidPolicy"},
  /**
   * Invalid time range specified in policy
   */
  81: {message:"InvalidTimeRange"},
  /**
   * Invalid not-after time specified
   */
  82: {message:"InvalidNotAfterTime"},
  /**
   * Requested resource was not found
   */
  100: {message:"NotFound"}
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
        "AAAAAQAAAAAAAAAAAAAAD1NpZ25hdHVyZVByb29mcwAAAAABAAAAAAAAAAEwAAAAAAAD7AAAB9AAAAAJU2lnbmVyS2V5AAAAAAAH0AAAAAtTaWduZXJQcm9vZgA=",
        "AAAAAgAAAAAAAAAAAAAACVNpZ25lcktleQAAAAAAAAEAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAIA==",
        "AAAAAgAAAAAAAAAAAAAABlNpZ25lcgAAAAAAAQAAAAEAAAAAAAAAB0VkMjU1MTkAAAAAAgAAB9AAAAANRWQyNTUxOVNpZ25lcgAAAAAAB9AAAAAKU2lnbmVyUm9sZQAA",
        "AAAAAQAAAB1FZDI1NTE5IHNpZ25lciBpbXBsZW1lbnRhdGlvbgAAAAAAAAAAAAANRWQyNTUxOVNpZ25lcgAAAAAAAAEAAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAAAg",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAEwAAACVDb250cmFjdCBoYXMgYWxyZWFkeSBiZWVuIGluaXRpYWxpemVkAAAAAAAAEkFscmVhZHlJbml0aWFsaXplZAAAAAAAAAAAACVDb250cmFjdCBoYXMgbm90IGJlZW4gaW5pdGlhbGl6ZWQgeWV0AAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAABAAAAG1N0b3JhZ2UgZW50cnkgd2FzIG5vdCBmb3VuZAAAAAAUU3RvcmFnZUVudHJ5Tm90Rm91bmQAAAAKAAAAHFN0b3JhZ2UgZW50cnkgYWxyZWFkeSBleGlzdHMAAAAZU3RvcmFnZUVudHJ5QWxyZWFkeUV4aXN0cwAAAAAAAAsAAAAoTm8gc2lnbmVycyBhcmUgY29uZmlndXJlZCBmb3IgdGhlIHdhbGxldAAAAAlOb1NpZ25lcnMAAAAAAAAUAAAAI1NpZ25lciBhbHJlYWR5IGV4aXN0cyBpbiB0aGUgd2FsbGV0AAAAABNTaWduZXJBbHJlYWR5RXhpc3RzAAAAABUAAAAiU2lnbmVyIHdhcyBub3QgZm91bmQgaW4gdGhlIHdhbGxldAAAAAAADlNpZ25lck5vdEZvdW5kAAAAAAAWAAAAKVNpZ25lciBoYXMgZXhwaXJlZCBhbmQgaXMgbm8gbG9uZ2VyIHZhbGlkAAAAAAAADVNpZ25lckV4cGlyZWQAAAAAAAAXAAAAAAAAABdDYW5ub3RSZXZva2VBZG1pblNpZ25lcgAAAAAYAAAAMk5vIG1hdGNoaW5nIHNpZ25hdHVyZSBmb3VuZCBmb3IgdGhlIGdpdmVuIGNyaXRlcmlhAAAAAAAZTWF0Y2hpbmdTaWduYXR1cmVOb3RGb3VuZAAAAAAAACgAAAAzU2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmYWlsZWQgZHVyaW5nIGF1dGhlbnRpY2F0aW9uAAAAABtTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQAAAAAKQAAABtJbnZhbGlkIHByb29mIHR5cGUgcHJvdmlkZWQAAAAAEEludmFsaWRQcm9vZlR5cGUAAAAqAAAAK05vIHByb29mcyBmb3VuZCBpbiB0aGUgYXV0aGVudGljYXRpb24gZW50cnkAAAAAE05vUHJvb2ZzSW5BdXRoRW50cnkAAAAAKwAAADtJbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgdG8gcGVyZm9ybSB0aGUgcmVxdWVzdGVkIG9wZXJhdGlvbgAAAAAXSW5zdWZmaWNpZW50UGVybWlzc2lvbnMAAAAAPAAAAC9JbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgZHVyaW5nIHdhbGxldCBjcmVhdGlvbgAAAAAhSW5zdWZmaWNpZW50UGVybWlzc2lvbnNPbkNyZWF0aW9uAAAAAAAAPQAAABxJbnZhbGlkIHBvbGljeSBjb25maWd1cmF0aW9uAAAADUludmFsaWRQb2xpY3kAAAAAAABQAAAAJkludmFsaWQgdGltZSByYW5nZSBzcGVjaWZpZWQgaW4gcG9saWN5AAAAAAAQSW52YWxpZFRpbWVSYW5nZQAAAFEAAAAgSW52YWxpZCBub3QtYWZ0ZXIgdGltZSBzcGVjaWZpZWQAAAATSW52YWxpZE5vdEFmdGVyVGltZQAAAABSAAAAIFJlcXVlc3RlZCByZXNvdXJjZSB3YXMgbm90IGZvdW5kAAAACE5vdEZvdW5kAAAAZA==",
        "AAAAAAAAAAAAAAANX19jb25zdHJ1Y3RvcgAAAAAAAAEAAAAAAAAAB3NpZ25lcnMAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAA",
        "AAAAAAAAAAAAAAAKYWRkX3NpZ25lcgAAAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAANdXBkYXRlX3NpZ25lcgAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAANcmV2b2tlX3NpZ25lcgAAAAAAAAEAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAp1DdXN0b20gYXV0aG9yaXphdGlvbiBmdW5jdGlvbiBpbnZva2VkIGJ5IHRoZSBTb3JvYmFuIHJ1bnRpbWUuCgpUaGlzIGZ1bmN0aW9uIGltcGxlbWVudHMgdGhlIHdhbGxldCdzIGF1dGhvcml6YXRpb24gbG9naWM6CjEuIFZlcmlmaWVzIHRoYXQgYWxsIHByb3ZpZGVkIHNpZ25hdHVyZXMgYXJlIGNyeXB0b2dyYXBoaWNhbGx5IHZhbGlkCjIuIENoZWNrcyB0aGF0IGF0IGxlYXN0IG9uZSBhdXRob3JpemVkIHNpZ25lciBoYXMgYXBwcm92ZWQgZWFjaCBvcGVyYXRpb24KMy4gRW5zdXJlcyBzaWduZXJzIGhhdmUgdGhlIHJlcXVpcmVkIHBlcm1pc3Npb25zIGZvciB0aGUgcmVxdWVzdGVkIG9wZXJhdGlvbnMKCiMgQXJndW1lbnRzCiogYGVudmAgLSBUaGUgY29udHJhY3QgZW52aXJvbm1lbnQKKiBgc2lnbmF0dXJlX3BheWxvYWRgIC0gSGFzaCBvZiB0aGUgZGF0YSB0aGF0IHdhcyBzaWduZWQKKiBgYXV0aF9wYXlsb2Fkc2AgLSBNYXAgb2Ygc2lnbmVyIGtleXMgdG8gdGhlaXIgc2lnbmF0dXJlIHByb29mcwoqIGBhdXRoX2NvbnRleHRzYCAtIExpc3Qgb2Ygb3BlcmF0aW9ucyBiZWluZyBhdXRob3JpemVkCgojIFJldHVybnMKKiBgT2soKCkpYCBpZiBhdXRob3JpemF0aW9uIHN1Y2NlZWRzCiogYEVycihFcnJvcilgIGlmIGF1dGhvcml6YXRpb24gZmFpbHMgZm9yIGFueSByZWFzb24AAAAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAANYXV0aF9wYXlsb2FkcwAAAAAAB9AAAAAPU2lnbmF0dXJlUHJvb2ZzAAAAAAAAAAANYXV0aF9jb250ZXh0cwAAAAAAA+oAAAfQAAAAB0NvbnRleHQAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
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