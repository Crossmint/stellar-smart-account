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


export interface Secp256r1Signature {
  authenticator_data: Buffer;
  client_data_json: Buffer;
  signature: Buffer;
}

export type SignerProof = {tag: "Ed25519", values: readonly [Buffer]} | {tag: "Secp256r1", values: readonly [Secp256r1Signature]};

export type SignatureProofs = readonly [Map<SignerKey, SignerProof>];

export type SignerKey = {tag: "Ed25519", values: readonly [Buffer]} | {tag: "Secp256r1", values: readonly [Buffer]};

export type Signer = {tag: "Ed25519", values: readonly [Ed25519Signer, SignerRole]} | {tag: "Secp256r1", values: readonly [Secp256r1Signer, SignerRole]};


/**
 * Ed25519 signer implementation
 */
export interface Ed25519Signer {
  public_key: Buffer;
}


export interface Secp256r1Signer {
  key_id: Buffer;
  public_key: Buffer;
}

export const Errors = {
  Initialization: {
    AlreadyInitialized: {message: "Contract has already been initialized"},
    NotInitialized: {message: "Contract has not been initialized yet"}
  },
  
  Storage: {
    EntryNotFound: {message: "Storage entry was not found"},
    EntryAlreadyExists: {message: "Storage entry already exists"}
  },
  
  SignerManagement: {
    NoSigners: {message: "No signers are configured for the wallet"},
    SignerAlreadyExists: {message: "Signer already exists in the wallet"},
    SignerNotFound: {message: "Signer was not found in the wallet"},
    SignerExpired: {message: "Signer has expired and is no longer valid"},
    CannotRevokeAdminSigner: {message: "Cannot revoke admin signer"},
    InsufficientPermissionsOnCreation: {message: "Insufficient permissions during wallet creation"}
  },
  
  Authentication: {
    MatchingSignatureNotFound: {message: "No matching signature found for the given criteria"},
    SignatureVerificationFailed: {message: "Signature verification failed during authentication"},
    InvalidProofType: {message: "Invalid proof type provided"},
    NoProofsInAuthEntry: {message: "No proofs found in the authentication entry"}
  },
  
  Permission: {
    InsufficientPermissions: {message: "Insufficient permissions to perform the requested operation"}
  },
  
  Policy: {
    InvalidPolicy: {message: "Invalid policy configuration"},
    InvalidTimeRange: {message: "Invalid time range specified in policy"},
    InvalidNotAfterTime: {message: "Invalid not-after time specified"}
  },
  
  Generic: {
    NotFound: {message: "Requested resource was not found"}
  }
}

export type StorageType = {tag: "Persistent", values: void} | {tag: "Instance", values: void};

export interface Client {
  /**
   * Construct and simulate a upgrade transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  upgrade: ({new_wasm_hash}: {new_wasm_hash: Buffer}, options?: {
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
  }) => Promise<AssembledTransaction<null>>

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
        "AAAAAQAAAAAAAAAAAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAAAAAAAwAAAAAAAAASYXV0aGVudGljYXRvcl9kYXRhAAAAAAAOAAAAAAAAABBjbGllbnRfZGF0YV9qc29uAAAADgAAAAAAAAAJc2lnbmF0dXJlAAAAAAAD7gAAAEA=",
        "AAAAAgAAAAAAAAAAAAAAC1NpZ25lclByb29mAAAAAAIAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAQAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAfQAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAA",
        "AAAAAQAAAAAAAAAAAAAAD1NpZ25hdHVyZVByb29mcwAAAAABAAAAAAAAAAEwAAAAAAAD7AAAB9AAAAAJU2lnbmVyS2V5AAAAAAAH0AAAAAtTaWduZXJQcm9vZgA=",
        "AAAAAgAAAAAAAAAAAAAACVNpZ25lcktleQAAAAAAAAIAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAIAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAAO",
        "AAAAAgAAAAAAAAAAAAAABlNpZ25lcgAAAAAAAgAAAAEAAAAAAAAAB0VkMjU1MTkAAAAAAgAAB9AAAAANRWQyNTUxOVNpZ25lcgAAAAAAB9AAAAAKU2lnbmVyUm9sZQAAAAAAAQAAAAAAAAAJU2VjcDI1NnIxAAAAAAAAAgAAB9AAAAAPU2VjcDI1NnIxU2lnbmVyAAAAB9AAAAAKU2lnbmVyUm9sZQAA",
        "AAAAAQAAAB1FZDI1NTE5IHNpZ25lciBpbXBsZW1lbnRhdGlvbgAAAAAAAAAAAAANRWQyNTUxOVNpZ25lcgAAAAAAAAEAAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAAAg",
        "AAAAAQAAAAAAAAAAAAAAD1NlY3AyNTZyMVNpZ25lcgAAAAACAAAAAAAAAAZrZXlfaWQAAAAAAA4AAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAABB",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAEwAAACVDb250cmFjdCBoYXMgYWxyZWFkeSBiZWVuIGluaXRpYWxpemVkAAAAAAAAEkFscmVhZHlJbml0aWFsaXplZAAAAAAAAAAAACVDb250cmFjdCBoYXMgbm90IGJlZW4gaW5pdGlhbGl6ZWQgeWV0AAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAABAAAAG1N0b3JhZ2UgZW50cnkgd2FzIG5vdCBmb3VuZAAAAAAUU3RvcmFnZUVudHJ5Tm90Rm91bmQAAAAKAAAAHFN0b3JhZ2UgZW50cnkgYWxyZWFkeSBleGlzdHMAAAAZU3RvcmFnZUVudHJ5QWxyZWFkeUV4aXN0cwAAAAAAAAsAAAAoTm8gc2lnbmVycyBhcmUgY29uZmlndXJlZCBmb3IgdGhlIHdhbGxldAAAAAlOb1NpZ25lcnMAAAAAAAAUAAAAI1NpZ25lciBhbHJlYWR5IGV4aXN0cyBpbiB0aGUgd2FsbGV0AAAAABNTaWduZXJBbHJlYWR5RXhpc3RzAAAAABUAAAAiU2lnbmVyIHdhcyBub3QgZm91bmQgaW4gdGhlIHdhbGxldAAAAAAADlNpZ25lck5vdEZvdW5kAAAAAAAWAAAAKVNpZ25lciBoYXMgZXhwaXJlZCBhbmQgaXMgbm8gbG9uZ2VyIHZhbGlkAAAAAAAADVNpZ25lckV4cGlyZWQAAAAAAAAXAAAAAAAAABdDYW5ub3RSZXZva2VBZG1pblNpZ25lcgAAAAAYAAAAMk5vIG1hdGNoaW5nIHNpZ25hdHVyZSBmb3VuZCBmb3IgdGhlIGdpdmVuIGNyaXRlcmlhAAAAAAAZTWF0Y2hpbmdTaWduYXR1cmVOb3RGb3VuZAAAAAAAACgAAAAzU2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmYWlsZWQgZHVyaW5nIGF1dGhlbnRpY2F0aW9uAAAAABtTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQAAAAAKQAAABtJbnZhbGlkIHByb29mIHR5cGUgcHJvdmlkZWQAAAAAEEludmFsaWRQcm9vZlR5cGUAAAAqAAAAK05vIHByb29mcyBmb3VuZCBpbiB0aGUgYXV0aGVudGljYXRpb24gZW50cnkAAAAAE05vUHJvb2ZzSW5BdXRoRW50cnkAAAAAKwAAADtJbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgdG8gcGVyZm9ybSB0aGUgcmVxdWVzdGVkIG9wZXJhdGlvbgAAAAAXSW5zdWZmaWNpZW50UGVybWlzc2lvbnMAAAAAPAAAAC9JbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgZHVyaW5nIHdhbGxldCBjcmVhdGlvbgAAAAAhSW5zdWZmaWNpZW50UGVybWlzc2lvbnNPbkNyZWF0aW9uAAAAAAAAPQAAABxJbnZhbGlkIHBvbGljeSBjb25maWd1cmF0aW9uAAAADUludmFsaWRQb2xpY3kAAAAAAABQAAAAJkludmFsaWQgdGltZSByYW5nZSBzcGVjaWZpZWQgaW4gcG9saWN5AAAAAAAQSW52YWxpZFRpbWVSYW5nZQAAAFEAAAAgSW52YWxpZCBub3QtYWZ0ZXIgdGltZSBzcGVjaWZpZWQAAAATSW52YWxpZE5vdEFmdGVyVGltZQAAAABSAAAAIFJlcXVlc3RlZCByZXNvdXJjZSB3YXMgbm90IGZvdW5kAAAACE5vdEZvdW5kAAAAZA==",
        "AAAAAAAAAAAAAAAHdXBncmFkZQAAAAABAAAAAAAAAA1uZXdfd2FzbV9oYXNoAAAAAAAD7gAAACAAAAAA",
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
    upgrade: this.txFromJSON<null>,
        add_signer: this.txFromJSON<Result<void>>,
        update_signer: this.txFromJSON<Result<void>>,
        revoke_signer: this.txFromJSON<Result<void>>
  }
}
