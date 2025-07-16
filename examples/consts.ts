import { hash, Keypair, Networks, rpc } from "@stellar/stellar-sdk";

export const NETWORK = Networks.TESTNET;
export const RPC_URL = "https://soroban-testnet.stellar.org";
export const SERVER = new rpc.Server(RPC_URL);
export const SA_WASM_HASH =
  "48b4c6cd009e8a95874441d63d0665dd85e1c2fc3e35290e2ab5e5dc95af1878";
export const FACTORY_WASM_HASH =
  "c1511ec621545450c2ffc38c174091231ef7a7f53a6d6353acc4f2ff5ee1cc48";

export const ADMIN_SIGNER_DERIVATION_PATH =
  "PLACEHOLDER_SIGNER_DERIVATION_PATH";
export const ADMIN_SIGNER_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from(ADMIN_SIGNER_DERIVATION_PATH))
);

export const DELEGATED_SIGNER_DERIVATION_PATH =
  "PLACEHOLDER_DELEGATED_SIGNER_DERIVATION_PATH";
export const DELEGATED_SIGNER_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from(DELEGATED_SIGNER_DERIVATION_PATH))
);

export const ROOT_DERIVATION_PATH = "PLACEHOLDER_ROOT_DERIVATION_PATH";
export const ROOT_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from(ROOT_DERIVATION_PATH))
);

export const DEPLOYER_DERIVATION_PATH = "PLACEHOLDER_DEPLOYER_DERIVATION_PATH";
export const DEPLOYER_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from(DEPLOYER_DERIVATION_PATH))
);

export const TREASURY_DERIVATION_PATH = "PLACEHOLDER_TREASURY_DERIVATION_PATH";
export const TREASURY_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from(TREASURY_DERIVATION_PATH))
);

export const CONSTRUCTOR_FUNC = "__constructor";

export const HELLO_WORLD_CONTRACT_ID =
  "CDDIVUUFADOLUWIKZE73O5XJFC6MMQHC7AA5YKZDJV2YDPUCO6O3MN34";
