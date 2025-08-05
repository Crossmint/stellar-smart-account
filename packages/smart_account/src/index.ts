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




export type SignerPolicy = {tag: "TimeBased", values: readonly [TimeBasedPolicy]} | {tag: "External", values: readonly [ExternalPolicy]};

export type SignerRole = {tag: "Admin", values: void} | {tag: "Standard", values: readonly [Array<SignerPolicy>]};


export interface ExternalPolicy {
  policy_address: string;
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
  /**
   * Contract has already been initialized
   */
  0: {message:"AlreadyInitialized"},
  /**
   * Contract has not been initialized yet
   */
  1: {message:"NotInitialized"},
  /**
   * Contract initialization failed
   */
  2: {message:"AccountInitializationFailed"},
  /**
   * Storage entry was not found
   */
  10: {message:"StorageEntryNotFound"},
  /**
   * Storage entry already exists
   */
  11: {message:"StorageEntryAlreadyExists"},
  /**
   * No signers are configured for the account
   */
  20: {message:"NoSigners"},
  /**
   * Signer already exists in the account
   */
  21: {message:"SignerAlreadyExists"},
  /**
   * Signer was not found in the account
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
   * Insufficient permissions during account creation
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
   * Policy client error
   */
  83: {message:"PolicyClientInitializationError"},
  /**
   * Plugin not found
   */
  100: {message:"PluginNotFound"},
  /**
   * Plugin already exists
   */
  101: {message:"PluginAlreadyInstalled"},
  /**
   * Plugin initialization failed
   */
  102: {message:"PluginInitializationFailed"},
  /**
   * Requested resource was not found
   */
  1000: {message:"NotFound"}
}


export interface SignerAddedEvent {
  signer: Signer;
  signer_key: SignerKey;
}


export interface SignerUpdatedEvent {
  new_signer: Signer;
  signer_key: SignerKey;
}


export interface SignerRevokedEvent {
  revoked_signer: Signer;
  signer_key: SignerKey;
}


export interface PluginInstalledEvent {
  plugin: string;
}


export interface PluginUninstalledEvent {
  plugin: string;
}

export type StorageType = {tag: "Persistent", values: void} | {tag: "Instance", values: void};

export type StorageOperation = {tag: "Store", values: void} | {tag: "Update", values: void} | {tag: "Delete", values: void};


export interface StorageChangeEvent {
  operation: StorageOperation;
  storage_type: StorageType;
}

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

  /**
   * Construct and simulate a install_plugin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  install_plugin: ({plugin}: {plugin: string}, options?: {
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
   * Construct and simulate a uninstall_plugin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  uninstall_plugin: ({plugin}: {plugin: string}, options?: {
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
   * Construct and simulate a is_deployed transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_deployed: (options?: {
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
  }) => Promise<AssembledTransaction<boolean>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {signers, plugins}: {signers: Array<Signer>, plugins: Array<string>},
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
    return ContractClient.deploy({signers, plugins}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAAAAAAAHdXBncmFkZQAAAAABAAAAAAAAAA1uZXdfd2FzbV9oYXNoAAAAAAAD7gAAACAAAAAA",
        "AAAAAAAAAAAAAAANX19jb25zdHJ1Y3RvcgAAAAAAAAIAAAAAAAAAB3NpZ25lcnMAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAAAAAAB3BsdWdpbnMAAAAD6gAAABMAAAAA",
        "AAAAAAAAAAAAAAAKYWRkX3NpZ25lcgAAAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAANdXBkYXRlX3NpZ25lcgAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAANcmV2b2tlX3NpZ25lcgAAAAAAAAEAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAAOaW5zdGFsbF9wbHVnaW4AAAAAAAEAAAAAAAAABnBsdWdpbgAAAAAAEwAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAAQdW5pbnN0YWxsX3BsdWdpbgAAAAEAAAAAAAAABnBsdWdpbgAAAAAAEwAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAAAAAAALaXNfZGVwbG95ZWQAAAAAAAAAAAEAAAAB",
        "AAAAAAAAAsRDdXN0b20gYXV0aG9yaXphdGlvbiBmdW5jdGlvbiBpbnZva2VkIGJ5IHRoZSBTb3JvYmFuIHJ1bnRpbWUuCgpUaGlzIGZ1bmN0aW9uIGltcGxlbWVudHMgdGhlIGFjY291bnQncyBhdXRob3JpemF0aW9uIGxvZ2ljIHdpdGggb3B0aW1pemF0aW9ucyBmb3IgU3RlbGxhciBjb3N0czoKMS4gVmVyaWZpZXMgdGhhdCBhbGwgcHJvdmlkZWQgc2lnbmF0dXJlcyBhcmUgY3J5cHRvZ3JhcGhpY2FsbHkgdmFsaWQKMi4gQ2hlY2tzIHRoYXQgYXQgbGVhc3Qgb25lIGF1dGhvcml6ZWQgc2lnbmVyIGhhcyBhcHByb3ZlZCBlYWNoIG9wZXJhdGlvbgozLiBFbnN1cmVzIHNpZ25lcnMgaGF2ZSB0aGUgcmVxdWlyZWQgcGVybWlzc2lvbnMgZm9yIHRoZSByZXF1ZXN0ZWQgb3BlcmF0aW9ucwoKCiMgQXJndW1lbnRzCiogYGVudmAgLSBUaGUgY29udHJhY3QgZW52aXJvbm1lbnQKKiBgc2lnbmF0dXJlX3BheWxvYWRgIC0gSGFzaCBvZiB0aGUgZGF0YSB0aGF0IHdhcyBzaWduZWQKKiBgYXV0aF9wYXlsb2Fkc2AgLSBNYXAgb2Ygc2lnbmVyIGtleXMgdG8gdGhlaXIgc2lnbmF0dXJlIHByb29mcwoqIGBhdXRoX2NvbnRleHRzYCAtIExpc3Qgb2Ygb3BlcmF0aW9ucyBiZWluZyBhdXRob3JpemVkCgojIFJldHVybnMKKiBgT2soKCkpYCBpZiBhdXRob3JpemF0aW9uIHN1Y2NlZWRzCiogYEVycihFcnJvcilgIGlmIGF1dGhvcml6YXRpb24gZmFpbHMgZm9yIGFueSByZWFzb24AAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAANYXV0aF9wYXlsb2FkcwAAAAAAB9AAAAAPU2lnbmF0dXJlUHJvb2ZzAAAAAAAAAAANYXV0aF9jb250ZXh0cwAAAAAAA+oAAAfQAAAAB0NvbnRleHQAAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAgAAAAAAAAAAAAAADFNpZ25lclBvbGljeQAAAAIAAAABAAAAAAAAAAlUaW1lQmFzZWQAAAAAAAABAAAH0AAAAA9UaW1lQmFzZWRQb2xpY3kAAAAAAQAAAAAAAAAIRXh0ZXJuYWwAAAABAAAH0AAAAA5FeHRlcm5hbFBvbGljeQAA",
        "AAAAAgAAAAAAAAAAAAAAClNpZ25lclJvbGUAAAAAAAMAAAAAAAAAAAAAAAVBZG1pbgAAAAAAAAAAAAAAAAAACFN0YW5kYXJkAAAAAQAAAAAAAAAKUmVzdHJpY3RlZAAAAAAAAQAAA+oAAAfQAAAADFNpZ25lclBvbGljeQ==",
        "AAAAAQAAAAAAAAAAAAAADkV4dGVybmFsUG9saWN5AAAAAAABAAAAAAAAAA5wb2xpY3lfYWRkcmVzcwAAAAAAEw==",
        "AAAAAQAAAAAAAAAAAAAAD1RpbWVCYXNlZFBvbGljeQAAAAACAAAAAAAAAAlub3RfYWZ0ZXIAAAAAAAAGAAAAAAAAAApub3RfYmVmb3JlAAAAAAAG",
        "AAAAAQAAAAAAAAAAAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAAAAAAAwAAAAAAAAASYXV0aGVudGljYXRvcl9kYXRhAAAAAAAOAAAAAAAAABBjbGllbnRfZGF0YV9qc29uAAAADgAAAAAAAAAJc2lnbmF0dXJlAAAAAAAD7gAAAEA=",
        "AAAAAgAAAAAAAAAAAAAAC1NpZ25lclByb29mAAAAAAIAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAQAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAfQAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAA",
        "AAAAAQAAAAAAAAAAAAAAD1NpZ25hdHVyZVByb29mcwAAAAABAAAAAAAAAAEwAAAAAAAD7AAAB9AAAAAJU2lnbmVyS2V5AAAAAAAH0AAAAAtTaWduZXJQcm9vZgA=",
        "AAAAAgAAAAAAAAAAAAAACVNpZ25lcktleQAAAAAAAAIAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAIAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAAO",
        "AAAAAgAAAAAAAAAAAAAABlNpZ25lcgAAAAAAAgAAAAEAAAAAAAAAB0VkMjU1MTkAAAAAAgAAB9AAAAANRWQyNTUxOVNpZ25lcgAAAAAAB9AAAAAKU2lnbmVyUm9sZQAAAAAAAQAAAAAAAAAJU2VjcDI1NnIxAAAAAAAAAgAAB9AAAAAPU2VjcDI1NnIxU2lnbmVyAAAAB9AAAAAKU2lnbmVyUm9sZQAA",
        "AAAAAQAAAB1FZDI1NTE5IHNpZ25lciBpbXBsZW1lbnRhdGlvbgAAAAAAAAAAAAANRWQyNTUxOVNpZ25lcgAAAAAAAAEAAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAAAg",
        "AAAAAQAAAAAAAAAAAAAAD1NlY3AyNTZyMVNpZ25lcgAAAAACAAAAAAAAAAZrZXlfaWQAAAAAAA4AAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAABB",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAGAAAACVDb250cmFjdCBoYXMgYWxyZWFkeSBiZWVuIGluaXRpYWxpemVkAAAAAAAAEkFscmVhZHlJbml0aWFsaXplZAAAAAAAAAAAACVDb250cmFjdCBoYXMgbm90IGJlZW4gaW5pdGlhbGl6ZWQgeWV0AAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAABAAAAHkNvbnRyYWN0IGluaXRpYWxpemF0aW9uIGZhaWxlZAAAAAAAG0FjY291bnRJbml0aWFsaXphdGlvbkZhaWxlZAAAAAACAAAAG1N0b3JhZ2UgZW50cnkgd2FzIG5vdCBmb3VuZAAAAAAUU3RvcmFnZUVudHJ5Tm90Rm91bmQAAAAKAAAAHFN0b3JhZ2UgZW50cnkgYWxyZWFkeSBleGlzdHMAAAAZU3RvcmFnZUVudHJ5QWxyZWFkeUV4aXN0cwAAAAAAAAsAAAApTm8gc2lnbmVycyBhcmUgY29uZmlndXJlZCBmb3IgdGhlIGFjY291bnQAAAAAAAAJTm9TaWduZXJzAAAAAAAAFAAAACRTaWduZXIgYWxyZWFkeSBleGlzdHMgaW4gdGhlIGFjY291bnQAAAATU2lnbmVyQWxyZWFkeUV4aXN0cwAAAAAVAAAAI1NpZ25lciB3YXMgbm90IGZvdW5kIGluIHRoZSBhY2NvdW50AAAAAA5TaWduZXJOb3RGb3VuZAAAAAAAFgAAAClTaWduZXIgaGFzIGV4cGlyZWQgYW5kIGlzIG5vIGxvbmdlciB2YWxpZAAAAAAAAA1TaWduZXJFeHBpcmVkAAAAAAAAFwAAAAAAAAAXQ2Fubm90UmV2b2tlQWRtaW5TaWduZXIAAAAAGAAAADJObyBtYXRjaGluZyBzaWduYXR1cmUgZm91bmQgZm9yIHRoZSBnaXZlbiBjcml0ZXJpYQAAAAAAGU1hdGNoaW5nU2lnbmF0dXJlTm90Rm91bmQAAAAAAAAoAAAAM1NpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkIGR1cmluZyBhdXRoZW50aWNhdGlvbgAAAAAbU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkAAAAACkAAAAbSW52YWxpZCBwcm9vZiB0eXBlIHByb3ZpZGVkAAAAABBJbnZhbGlkUHJvb2ZUeXBlAAAAKgAAACtObyBwcm9vZnMgZm91bmQgaW4gdGhlIGF1dGhlbnRpY2F0aW9uIGVudHJ5AAAAABNOb1Byb29mc0luQXV0aEVudHJ5AAAAACsAAAA7SW5zdWZmaWNpZW50IHBlcm1pc3Npb25zIHRvIHBlcmZvcm0gdGhlIHJlcXVlc3RlZCBvcGVyYXRpb24AAAAAF0luc3VmZmljaWVudFBlcm1pc3Npb25zAAAAADwAAAAwSW5zdWZmaWNpZW50IHBlcm1pc3Npb25zIGR1cmluZyBhY2NvdW50IGNyZWF0aW9uAAAAIUluc3VmZmljaWVudFBlcm1pc3Npb25zT25DcmVhdGlvbgAAAAAAAD0AAAAcSW52YWxpZCBwb2xpY3kgY29uZmlndXJhdGlvbgAAAA1JbnZhbGlkUG9saWN5AAAAAAAAUAAAACZJbnZhbGlkIHRpbWUgcmFuZ2Ugc3BlY2lmaWVkIGluIHBvbGljeQAAAAAAEEludmFsaWRUaW1lUmFuZ2UAAABRAAAAIEludmFsaWQgbm90LWFmdGVyIHRpbWUgc3BlY2lmaWVkAAAAE0ludmFsaWROb3RBZnRlclRpbWUAAAAAUgAAABNQb2xpY3kgY2xpZW50IGVycm9yAAAAAB9Qb2xpY3lDbGllbnRJbml0aWFsaXphdGlvbkVycm9yAAAAAFMAAAAQUGx1Z2luIG5vdCBmb3VuZAAAAA5QbHVnaW5Ob3RGb3VuZAAAAAAAZAAAABVQbHVnaW4gYWxyZWFkeSBleGlzdHMAAAAAAAAWUGx1Z2luQWxyZWFkeUluc3RhbGxlZAAAAAAAZQAAABxQbHVnaW4gaW5pdGlhbGl6YXRpb24gZmFpbGVkAAAAGlBsdWdpbkluaXRpYWxpemF0aW9uRmFpbGVkAAAAAABmAAAAIFJlcXVlc3RlZCByZXNvdXJjZSB3YXMgbm90IGZvdW5kAAAACE5vdEZvdW5kAAAD6A==",
        "AAAAAQAAAAAAAAAAAAAAEFNpZ25lckFkZGVkRXZlbnQAAAACAAAAAAAAAAZzaWduZXIAAAAAB9AAAAAGU2lnbmVyAAAAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAA",
        "AAAAAQAAAAAAAAAAAAAAElNpZ25lclVwZGF0ZWRFdmVudAAAAAAAAgAAAAAAAAAKbmV3X3NpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAKc2lnbmVyX2tleQAAAAAH0AAAAAlTaWduZXJLZXkAAAA=",
        "AAAAAQAAAAAAAAAAAAAAElNpZ25lclJldm9rZWRFdmVudAAAAAAAAgAAAAAAAAAOcmV2b2tlZF9zaWduZXIAAAAAB9AAAAAGU2lnbmVyAAAAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAA",
        "AAAAAQAAAAAAAAAAAAAAFFBsdWdpbkluc3RhbGxlZEV2ZW50AAAAAQAAAAAAAAAGcGx1Z2luAAAAAAAT",
        "AAAAAQAAAAAAAAAAAAAAFlBsdWdpblVuaW5zdGFsbGVkRXZlbnQAAAAAAAEAAAAAAAAABnBsdWdpbgAAAAAAEw==",
        "AAAAAgAAAAAAAAAAAAAAC1N0b3JhZ2VUeXBlAAAAAAIAAAAAAAAAAAAAAApQZXJzaXN0ZW50AAAAAAAAAAAAAAAAAAhJbnN0YW5jZQ==",
        "AAAAAgAAAAAAAAAAAAAAEFN0b3JhZ2VPcGVyYXRpb24AAAADAAAAAAAAAAAAAAAFU3RvcmUAAAAAAAAAAAAAAAAAAAZVcGRhdGUAAAAAAAAAAAAAAAAABkRlbGV0ZQAA",
        "AAAAAQAAAAAAAAAAAAAAElN0b3JhZ2VDaGFuZ2VFdmVudAAAAAAAAgAAAAAAAAAJb3BlcmF0aW9uAAAAAAAH0AAAABBTdG9yYWdlT3BlcmF0aW9uAAAAAAAAAAxzdG9yYWdlX3R5cGUAAAfQAAAAC1N0b3JhZ2VUeXBlAA==" ]),
      options
    )
  }
  public readonly fromJSON = {
    upgrade: this.txFromJSON<null>,
        add_signer: this.txFromJSON<Result<void>>,
        update_signer: this.txFromJSON<Result<void>>,
        revoke_signer: this.txFromJSON<Result<void>>,
        install_plugin: this.txFromJSON<Result<void>>,
        uninstall_plugin: this.txFromJSON<Result<void>>,
        is_deployed: this.txFromJSON<boolean>
  }
}
