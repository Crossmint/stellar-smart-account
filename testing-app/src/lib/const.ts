import { Asset } from "@stellar/stellar-sdk";
import { USDXM_ISSUER_WALLET } from "./wallets";

export const RPC_URL = "https://soroban-testnet.stellar.org";

export const XM_USD_ASSET = new Asset("XMUSD", USDXM_ISSUER_WALLET.publicKey());
