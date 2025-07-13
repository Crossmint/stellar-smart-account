import { hash, Keypair, Networks, rpc } from "@stellar/stellar-sdk";

export const NETWORK = Networks.TESTNET;
export const RPC_URL = "https://soroban-testnet.stellar.org";
export const SERVER = new rpc.Server(RPC_URL);
export const SW_WASM_HASH =
  "4b4069358eaf316a6d9489192556af932709d297dfb25a9590456fc4abf5a020";
export const SW_WASM_HASH_TESTING =
  "58eef10c6b83ef524fccb421b9b0f4631366cfe5ff1b747378e734869bf59cd4";
export const FACTORY_WASM_HASH =
  "aec59d18628f303aa09beb8c91a0e488d3b775f2b96c17af3998a85135b2251a";

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

export const HELLO_WORLD_WASM_HASH =
  "f386de20016af78e9f89119ed1eeb5e0e2e0274050d89f28cb36c4d4bb236e73";
export const HELLO_WORLD_CONTRACT_ID =
  "CDDIVUUFADOLUWIKZE73O5XJFC6MMQHC7AA5YKZDJV2YDPUCO6O3MN34";
