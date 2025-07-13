import { hash, Keypair, Networks, rpc } from "@stellar/stellar-sdk";

export const NETWORK = Networks.TESTNET;
export const RPC_URL = "https://soroban-testnet.stellar.org";
export const SERVER = new rpc.Server(RPC_URL);
export const SW_WASM_HASH =
  "a2ab113b01005162e48519af6e83d01505b8118ae6f39dd18756b4f258970276";
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

export const HELLO_WORLD_CONTRACT_ID =
  "CDDIVUUFADOLUWIKZE73O5XJFC6MMQHC7AA5YKZDJV2YDPUCO6O3MN34";
