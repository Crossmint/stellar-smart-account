import { Buffer } from "buffer";
import { Client as ContractClient, Spec as ContractSpec, } from '@stellar/stellar-sdk/contract';
export * from '@stellar/stellar-sdk';
export * as contract from '@stellar/stellar-sdk/contract';
export * as rpc from '@stellar/stellar-sdk/rpc';
if (typeof window !== 'undefined') {
    //@ts-ignore Buffer exists
    window.Buffer = window.Buffer || Buffer;
}
export const AccessControlError = {
    1210: { message: "Unauthorized" },
    1211: { message: "AdminNotSet" },
    1212: { message: "IndexOutOfBounds" },
    1213: { message: "AdminRoleNotFound" },
    1214: { message: "RoleCountIsNotZero" },
    1215: { message: "RoleNotFound" },
    1216: { message: "AdminAlreadySet" },
    1217: { message: "RoleNotHeld" },
    1218: { message: "RoleIsEmpty" }
};
export class Client extends ContractClient {
    options;
    static async deploy(
    /** Constructor/Initialization Args for the contract's `__constructor` method */
    { admin }, 
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options) {
        return ContractClient.deploy({ admin }, options);
    }
    constructor(options) {
        super(new ContractSpec(["AAAAAAAAADJDb25zdHJ1Y3QgdGhlIGRlcGxveWVyIHdpdGggYSBnaXZlbiBhZG1pbiBhZGRyZXNzLgAAAAAADV9fY29uc3RydWN0b3IAAAAAAAABAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAA",
            "AAAAAAAAAI1EZXBsb3lzIHRoZSBjb250cmFjdCBvbiBiZWhhbGYgb2YgdGhlIGBDcm9zc21pbnRDb250cmFjdEZhY3RvcnlgIGNvbnRyYWN0LgoKVGhpcyBoYXMgdG8gYmUgYXV0aG9yaXplZCBieSBhbiBhZGRyZXNzIHdpdGggdGhlIGBkZXBsb3llcmAgcm9sZS4AAAAAAAAGZGVwbG95AAAAAAAEAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAACXdhc21faGFzaAAAAAAAA+4AAAAgAAAAAAAAAARzYWx0AAAD7gAAACAAAAAAAAAAEGNvbnN0cnVjdG9yX2FyZ3MAAAPqAAAAAAAAAAEAAAAT",
            "AAAAAAAAALJVcGxvYWRzIHRoZSBjb250cmFjdCBXQVNNIGFuZCBkZXBsb3lzIGl0IG9uIGJlaGFsZiBvZiB0aGUgYENyb3NzbWludENvbnRyYWN0RmFjdG9yeWAgY29udHJhY3QuCgp1c2luZyB0aGF0IGhhc2guIFRoaXMgaGFzIHRvIGJlIGF1dGhvcml6ZWQgYnkgYW4gYWRkcmVzcyB3aXRoIHRoZSBgZGVwbG95ZXJgIHJvbGUuAAAAAAARdXBsb2FkX2FuZF9kZXBsb3kAAAAAAAAEAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAACndhc21fYnl0ZXMAAAAAAA4AAAAAAAAABHNhbHQAAAPuAAAAIAAAAAAAAAAQY29uc3RydWN0b3JfYXJncwAAA+oAAAAAAAAAAQAAABM=",
            "AAAAAAAAAAAAAAAUZ2V0X2RlcGxveWVkX2FkZHJlc3MAAAABAAAAAAAAAARzYWx0AAAD7gAAACAAAAABAAAAEw==",
            "AAAAAAAAAAAAAAAIaGFzX3JvbGUAAAACAAAAAAAAAAdhY2NvdW50AAAAABMAAAAAAAAABHJvbGUAAAARAAAAAQAAA+gAAAAE",
            "AAAAAAAAAAAAAAAVZ2V0X3JvbGVfbWVtYmVyX2NvdW50AAAAAAAAAQAAAAAAAAAEcm9sZQAAABEAAAABAAAABA==",
            "AAAAAAAAAAAAAAAPZ2V0X3JvbGVfbWVtYmVyAAAAAAIAAAAAAAAABHJvbGUAAAARAAAAAAAAAAVpbmRleAAAAAAAAAQAAAABAAAAEw==",
            "AAAAAAAAAAAAAAAOZ2V0X3JvbGVfYWRtaW4AAAAAAAEAAAAAAAAABHJvbGUAAAARAAAAAQAAA+gAAAAR",
            "AAAAAAAAAAAAAAAJZ2V0X2FkbWluAAAAAAAAAAAAAAEAAAPoAAAAEw==",
            "AAAAAAAAAAAAAAAKZ3JhbnRfcm9sZQAAAAAAAwAAAAAAAAAGY2FsbGVyAAAAAAATAAAAAAAAAAdhY2NvdW50AAAAABMAAAAAAAAABHJvbGUAAAARAAAAAA==",
            "AAAAAAAAAAAAAAALcmV2b2tlX3JvbGUAAAAAAwAAAAAAAAAGY2FsbGVyAAAAAAATAAAAAAAAAAdhY2NvdW50AAAAABMAAAAAAAAABHJvbGUAAAARAAAAAA==",
            "AAAAAAAAAAAAAAANcmVub3VuY2Vfcm9sZQAAAAAAAAIAAAAAAAAABmNhbGxlcgAAAAAAEwAAAAAAAAAEcm9sZQAAABEAAAAA",
            "AAAAAAAAAAAAAAAOcmVub3VuY2VfYWRtaW4AAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAATdHJhbnNmZXJfYWRtaW5fcm9sZQAAAAACAAAAAAAAAAluZXdfYWRtaW4AAAAAAAATAAAAAAAAABFsaXZlX3VudGlsX2xlZGdlcgAAAAAAAAQAAAAA",
            "AAAAAAAAAAAAAAAVYWNjZXB0X2FkbWluX3RyYW5zZmVyAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAOc2V0X3JvbGVfYWRtaW4AAAAAAAIAAAAAAAAABHJvbGUAAAARAAAAAAAAAAphZG1pbl9yb2xlAAAAAAARAAAAAA==",
            "AAAABAAAAAAAAAAAAAAAEkFjY2Vzc0NvbnRyb2xFcnJvcgAAAAAACQAAAAAAAAAMVW5hdXRob3JpemVkAAAEugAAAAAAAAALQWRtaW5Ob3RTZXQAAAAEuwAAAAAAAAAQSW5kZXhPdXRPZkJvdW5kcwAABLwAAAAAAAAAEUFkbWluUm9sZU5vdEZvdW5kAAAAAAAEvQAAAAAAAAASUm9sZUNvdW50SXNOb3RaZXJvAAAAAAS+AAAAAAAAAAxSb2xlTm90Rm91bmQAAAS/AAAAAAAAAA9BZG1pbkFscmVhZHlTZXQAAAAEwAAAAAAAAAALUm9sZU5vdEhlbGQAAAAEwQAAAAAAAAALUm9sZUlzRW1wdHkAAAAEwg==",
            "AAAAAQAAADFTdG9yYWdlIGtleSBmb3IgZW51bWVyYXRpb24gb2YgYWNjb3VudHMgcGVyIHJvbGUuAAAAAAAAAAAAAA5Sb2xlQWNjb3VudEtleQAAAAAAAgAAAAAAAAAFaW5kZXgAAAAAAAAEAAAAAAAAAARyb2xlAAAAEQ==",
            "AAAAAgAAADxTdG9yYWdlIGtleXMgZm9yIHRoZSBkYXRhIGFzc29jaWF0ZWQgd2l0aCB0aGUgYWNjZXNzIGNvbnRyb2wAAAAAAAAAF0FjY2Vzc0NvbnRyb2xTdG9yYWdlS2V5AAAAAAYAAAABAAAAAAAAAAxSb2xlQWNjb3VudHMAAAABAAAH0AAAAA5Sb2xlQWNjb3VudEtleQAAAAAAAQAAAAAAAAAHSGFzUm9sZQAAAAACAAAAEwAAABEAAAABAAAAAAAAABFSb2xlQWNjb3VudHNDb3VudAAAAAAAAAEAAAARAAAAAQAAAAAAAAAJUm9sZUFkbWluAAAAAAAAAQAAABEAAAAAAAAAAAAAAAVBZG1pbgAAAAAAAAAAAAAAAAAADFBlbmRpbmdBZG1pbg=="]), options);
        this.options = options;
    }
    fromJSON = {
        deploy: (this.txFromJSON),
        upload_and_deploy: (this.txFromJSON),
        get_deployed_address: (this.txFromJSON),
        has_role: (this.txFromJSON),
        get_role_member_count: (this.txFromJSON),
        get_role_member: (this.txFromJSON),
        get_role_admin: (this.txFromJSON),
        get_admin: (this.txFromJSON),
        grant_role: (this.txFromJSON),
        revoke_role: (this.txFromJSON),
        renounce_role: (this.txFromJSON),
        renounce_admin: (this.txFromJSON),
        transfer_admin_role: (this.txFromJSON),
        accept_admin_transfer: (this.txFromJSON),
        set_role_admin: (this.txFromJSON)
    };
}
