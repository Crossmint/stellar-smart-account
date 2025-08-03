import { hash, Keypair, Networks, rpc } from "@stellar/stellar-sdk";

export const NETWORK = Networks.TESTNET;
export const RPC_URL = "https://soroban-testnet.stellar.org";
export const SERVER = new rpc.Server(RPC_URL);
export const SA_WASM_HASH =
  "47253acad1fc948dd1f49e67672ca179ba18b76669e4fa79664c520b663548a2";
export const FACTORY_WASM_HASH =
  "5610c6af5c162a6b5aaeab2cec15de7bcc5d827d3e42bdaff7d839038493756b";
export const POLICY_WASM_HASH =
  "7ef8802747c5cb00632453dcdec88cfbd7033c9eab1e7ac40c86865b6d583963";
export const HELLO_WORLD_CONTRACT_WASM_HASH =
  "f386de20016af78e9f89119ed1eeb5e0e2e0274050d89f28cb36c4d4bb236e73";

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
