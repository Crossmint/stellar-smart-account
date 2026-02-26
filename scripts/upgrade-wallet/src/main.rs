//! CLI tool for upgrading a v1.0.0 Smart Account to v2.
//!
//! Uses the Stellar Rust SDK (`stellar-rpc-client` + `stellar-xdr`) for all RPC
//! communication and transaction building. No dependency on the `stellar` CLI binary
//! for transaction operations.
//!
//! The two-phase upgrade process:
//! 1. Upload the v2 WASM binary to the ledger
//! 2. Call `upgrade(new_wasm_hash)` on the smart account
//! 3. Call `migrate(migration_data)` with the list of signers to migrate
//!
//! # Usage
//!
//! ```bash
//! # Auto-discover signers from on-chain storage (requires stellar CLI for storage read)
//! upgrade-wallet \
//!   --rpc-url https://soroban-testnet.stellar.org \
//!   --network-passphrase "Test SDF Network ; September 2015" \
//!   --source-account SC...SECRET \
//!   --contract-id CA...ADDR \
//!   --wasm-path ./smart_account_v2.wasm \
//!   --auto-discover
//!
//! # Manual signer specification
//! upgrade-wallet \
//!   --rpc-url https://soroban-testnet.stellar.org \
//!   --network-passphrase "Test SDF Network ; September 2015" \
//!   --source-account SC...SECRET \
//!   --contract-id CA...ADDR \
//!   --wasm-path ./smart_account_v2.wasm \
//!   --migrate-secp256r1 "key_id_hex_1" \
//!   --migrate-ed25519 "pubkey_hex_1"
//! ```

use clap::Parser;
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractDataDurability, ContractId, DecoratedSignature, Hash, HashIdPreimage,
    HashIdPreimageSorobanAuthorization, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
    LedgerKey, LedgerKeyContractData, Limits, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    SequenceNumber, Signature as XdrSignature, SignatureHint, SorobanAuthorizationEntry,
    SorobanCredentials, SorobanTransactionData, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

/// CLI tool for upgrading a v1 Smart Account wallet to v2 via Stellar SDK.
#[derive(Parser, Debug)]
#[command(name = "upgrade-wallet")]
#[command(about = "Upgrade a v1.0.0 Smart Account to v2 with optional data migration")]
struct Cli {
    /// RPC server endpoint (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, env = "STELLAR_RPC_URL")]
    rpc_url: String,

    /// Network passphrase (e.g. "Test SDF Network ; September 2015")
    #[arg(long, env = "STELLAR_NETWORK_PASSPHRASE")]
    network_passphrase: String,

    /// Source account secret key (SC...). Must be an Ed25519 admin signer of the smart account.
    #[arg(long, env = "STELLAR_ACCOUNT")]
    source_account: String,

    /// The smart account contract address to upgrade (CA...).
    #[arg(long)]
    contract_id: String,

    /// Path to the v2 WASM binary (required unless --wasm-hash is provided)
    #[arg(long)]
    wasm_path: Option<String>,

    /// Auto-discover signers from on-chain storage via the stellar CLI.
    /// Requires the `stellar` CLI to be installed for the storage read.
    #[arg(long, default_value_t = false)]
    auto_discover: bool,

    /// Hex-encoded key_id values of Secp256r1 signers to migrate to Webauthn (comma-separated)
    #[arg(long, value_delimiter = ',')]
    migrate_secp256r1: Vec<String>,

    /// Hex-encoded public keys of Ed25519 signers that need policy migration (comma-separated)
    #[arg(long, value_delimiter = ',')]
    migrate_ed25519: Vec<String>,

    /// Skip the upload step if the WASM is already on the ledger. Provide the wasm hash directly.
    #[arg(long)]
    wasm_hash: Option<String>,

    /// Perform a dry-run: simulate only, don't submit transactions.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Holds the discovered signer keys for migration.
#[derive(Debug, Default)]
struct DiscoveredSigners {
    ed25519: Vec<String>,
    secp256r1: Vec<String>,
}

/// Wraps the RPC client with signing capabilities.
struct StellarClient {
    rpc: Client,
    signing_key: ed25519_dalek::SigningKey,
    source_public: [u8; 32],
    network_id: Hash,
}

impl StellarClient {
    fn new(rpc_url: &str, secret_key_str: &str, network_passphrase: &str) -> Result<Self, String> {
        let rpc = Client::new(rpc_url).map_err(|e| format!("Failed to create RPC client: {e}"))?;

        // Decode the secret key
        let secret_key = stellar_strkey::ed25519::PrivateKey::from_string(secret_key_str)
            .map_err(|e| format!("Invalid secret key: {e}"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key.0);
        let source_public = ed25519_dalek::VerifyingKey::from(&signing_key).to_bytes();

        // Compute network ID (SHA-256 of passphrase)
        let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());

        Ok(Self {
            rpc,
            signing_key,
            source_public,
            network_id,
        })
    }

    /// Get the source account's sequence number.
    async fn get_sequence(&self) -> Result<i64, String> {
        let pk_str = stellar_strkey::ed25519::PublicKey(self.source_public).to_string();
        let account = self
            .rpc
            .get_account(&pk_str)
            .await
            .map_err(|e| format!("Failed to get account: {e}"))?;
        Ok(account.seq_num.0)
    }

    /// Get the latest ledger number.
    async fn get_latest_ledger(&self) -> Result<u32, String> {
        let resp = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| format!("Failed to get latest ledger: {e}"))?;
        Ok(resp.sequence)
    }

    /// Build a transaction with a single operation.
    fn build_transaction(&self, seq: i64, op: Operation, fee: u32) -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(self.source_public)),
            fee,
            seq_num: SequenceNumber(seq + 1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().expect("single operation"),
            ext: TransactionExt::V0,
        }
    }

    /// Wrap a transaction in an envelope with an empty signature (for simulation).
    fn envelope_for_simulation(&self, tx: &Transaction) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: VecM::default(),
        })
    }

    /// Simulate a transaction and return: (transaction_data, auth_entries, min_resource_fee).
    ///
    /// Adds safety margins to resource limits: the simulation gives estimates that
    /// may be too tight for actual on-chain execution, especially for operations
    /// like `update_current_contract_wasm` that require significant resources.
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<(SorobanTransactionData, Vec<SorobanAuthorizationEntry>, i64), String> {
        let resp = self
            .rpc
            .simulate_transaction_envelope(envelope, None)
            .await
            .map_err(|e| format!("Simulation failed: {e}"))?;

        // Decode transaction data and add resource safety margins
        let mut tx_data =
            SorobanTransactionData::from_xdr_base64(&resp.transaction_data, Limits::none())
                .map_err(|e| format!("Failed to decode transaction data: {e}"))?;

        // Add 25% buffer to CPU instructions and 20% to read/write bytes
        tx_data.resources.instructions = tx_data
            .resources
            .instructions
            .saturating_add(tx_data.resources.instructions / 4);
        tx_data.resources.disk_read_bytes = tx_data
            .resources
            .disk_read_bytes
            .saturating_add(tx_data.resources.disk_read_bytes / 5);
        tx_data.resources.write_bytes = tx_data
            .resources
            .write_bytes
            .saturating_add(tx_data.resources.write_bytes / 5);
        // Add 15% buffer to resource fee
        tx_data.resource_fee = tx_data
            .resource_fee
            .saturating_add(tx_data.resource_fee / 7);

        // Collect auth entries from all results
        let mut auth_entries = Vec::new();
        for result in &resp.results {
            for auth_xdr in &result.auth {
                let entry = SorobanAuthorizationEntry::from_xdr_base64(auth_xdr, Limits::none())
                    .map_err(|e| format!("Failed to decode auth entry: {e}"))?;
                auth_entries.push(entry);
            }
        }

        // Also add a buffer to the min_resource_fee
        let buffered_fee = resp
            .min_resource_fee
            .saturating_add(resp.min_resource_fee / 5);
        Ok((tx_data, auth_entries, buffered_fee as i64))
    }

    /// Sign the authorization entries for the smart account.
    ///
    /// For each entry with `SorobanCredentials::Address` pointing to the contract,
    /// computes the authorization preimage hash, signs with ED25519, and builds
    /// the `SignatureProofs` ScVal expected by the smart account's `__check_auth`.
    fn sign_auth_entries(
        &self,
        entries: Vec<SorobanAuthorizationEntry>,
        latest_ledger: u32,
    ) -> Result<Vec<SorobanAuthorizationEntry>, String> {
        entries
            .into_iter()
            .map(|mut entry| {
                if let SorobanCredentials::Address(addr_creds) = &mut entry.credentials {
                    // Set signature expiration
                    addr_creds.signature_expiration_ledger = latest_ledger + 100;

                    // Compute the authorization preimage hash
                    let preimage =
                        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                            network_id: self.network_id.clone(),
                            nonce: addr_creds.nonce,
                            signature_expiration_ledger: addr_creds.signature_expiration_ledger,
                            invocation: entry.root_invocation.clone(),
                        });
                    let preimage_xdr = preimage
                        .to_xdr(Limits::none())
                        .map_err(|e| format!("Failed to encode auth preimage: {e}"))?;
                    let payload_hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();

                    // Sign with ED25519
                    let signature = self.signing_key.sign(&payload_hash);

                    // Build the SignatureProofs ScVal for the smart account's __check_auth
                    let proofs_scval =
                        build_signature_proofs_scval(&self.source_public, &signature.to_bytes());
                    addr_creds.signature = proofs_scval;
                }
                Ok(entry)
            })
            .collect()
    }

    /// Sign the transaction envelope with the source account key.
    fn sign_envelope(&self, tx: &Transaction) -> TransactionEnvelope {
        // Build the signature payload
        let sig_payload = TransactionSignaturePayload {
            network_id: self.network_id.clone(),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        let sig_payload_xdr = sig_payload
            .to_xdr(Limits::none())
            .expect("XDR encoding cannot fail");
        let hash: [u8; 32] = Sha256::digest(&sig_payload_xdr).into();

        // Sign
        let signature = self.signing_key.sign(&hash);

        // Build the hint (last 4 bytes of public key)
        let hint = SignatureHint(self.source_public[28..32].try_into().unwrap());

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: vec![DecoratedSignature {
                hint,
                signature: XdrSignature(
                    signature.to_bytes().to_vec().try_into().expect("64 bytes"),
                ),
            }]
            .try_into()
            .expect("single signature"),
        })
    }

    /// Upload a WASM binary to the ledger and return its hash.
    async fn upload_wasm(&self, wasm: &[u8]) -> Result<[u8; 32], String> {
        let seq = self.get_sequence().await?;

        // Build the UploadContractWasm host function
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(
                    wasm.to_vec().try_into().map_err(|_| "WASM too large")?,
                ),
                auth: VecM::default(),
            }),
        };

        let tx = self.build_transaction(seq, op, 100);
        let sim_envelope = self.envelope_for_simulation(&tx);
        let (tx_data, _auth_entries, min_fee) = self.simulate(&sim_envelope).await?;

        // Rebuild transaction with simulation data
        let op_with_auth = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(
                    wasm.to_vec().try_into().map_err(|_| "WASM too large")?,
                ),
                auth: VecM::default(),
            }),
        };
        let mut final_tx = self.build_transaction(seq, op_with_auth, 100 + min_fee as u32);
        final_tx.ext = TransactionExt::V1(tx_data);

        let signed = self.sign_envelope(&final_tx);

        // Submit
        let resp = self
            .rpc
            .send_transaction_polling(&signed)
            .await
            .map_err(|e| format!("Upload failed: {e}"))?;

        // Compute the WASM hash (SHA-256 of the WASM bytes)
        let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
        println!("  WASM hash: {}", hex::encode(wasm_hash));
        if let Some(ledger) = resp.ledger {
            println!("  Included in ledger {ledger}");
        }
        Ok(wasm_hash)
    }

    /// Invoke a contract function with the given arguments.
    ///
    /// `extra_read_keys` allows injecting additional `LedgerKey`s into the
    /// read-only footprint. This is necessary for custom account contracts
    /// because simulation does NOT call `__check_auth`, so any storage entries
    /// read during auth verification (e.g. signer keys) won't appear in the
    /// simulated footprint. Without them, real execution traps when
    /// `__check_auth` tries to read the signer from persistent storage.
    ///
    /// Two-pass approach: first simulate to get auth entries, sign them,
    /// then re-simulate the complete transaction (with signed auth + extra
    /// footprint) to get accurate resource estimates.
    async fn invoke_contract(
        &self,
        contract_id: &[u8; 32],
        function: &str,
        args: Vec<ScVal>,
        extra_read_keys: Vec<LedgerKey>,
    ) -> Result<(), String> {
        let seq = self.get_sequence().await?;
        let latest_ledger = self.get_latest_ledger().await?;

        let invoke_args = InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(*contract_id))),
            function_name: ScSymbol(function.try_into().map_err(|_| "function name too long")?),
            args: args.try_into().map_err(|_| "too many args")?,
        };

        // === Pass 1: simulate to get auth entries ===
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke_args.clone()),
                auth: VecM::default(),
            }),
        };

        let tx = self.build_transaction(seq, op, 100);
        let sim_envelope = self.envelope_for_simulation(&tx);
        let (_tx_data, auth_entries, _min_fee) = self.simulate(&sim_envelope).await?;

        // Sign the auth entries
        let signed_auth = self.sign_auth_entries(auth_entries, latest_ledger)?;

        // === Pass 2: re-simulate with signed auth to get accurate resources ===
        // Build the transaction with signed auth entries so simulation sees the
        // full picture (including auth-related storage reads).
        let op_with_auth = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke_args.clone()),
                auth: signed_auth
                    .clone()
                    .try_into()
                    .map_err(|_| "too many auth entries")?,
            }),
        };
        let tx2 = self.build_transaction(seq, op_with_auth, 100);
        let sim_envelope2 = self.envelope_for_simulation(&tx2);
        let (mut tx_data, _auth2, _min_fee2) = self.simulate(&sim_envelope2).await?;

        // Add any extra read keys that the simulation might still miss
        if !extra_read_keys.is_empty() {
            let mut read_only: Vec<LedgerKey> = tx_data.resources.footprint.read_only.to_vec();

            for key in &extra_read_keys {
                if !read_only.contains(key) {
                    read_only.push(key.clone());
                }
            }

            tx_data.resources.footprint.read_only = read_only
                .try_into()
                .map_err(|_| "too many read-only footprint entries")?;

            // Add modest headroom for the extra footprint entries.
            let extra_bytes = (extra_read_keys.len() as u32) * 2000;
            tx_data.resources.disk_read_bytes = tx_data
                .resources
                .disk_read_bytes
                .saturating_add(extra_bytes);
            tx_data.resource_fee = tx_data.resource_fee.saturating_add(200_000);
        }

        // Build the final transaction
        let final_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke_args),
                auth: signed_auth
                    .try_into()
                    .map_err(|_| "too many auth entries")?,
            }),
        };
        let tx_fee = 100u32.saturating_add(tx_data.resource_fee as u32);
        let mut final_tx = self.build_transaction(seq, final_op, tx_fee);
        final_tx.ext = TransactionExt::V1(tx_data);

        let signed = self.sign_envelope(&final_tx);

        let resp = self
            .rpc
            .send_transaction_polling(&signed)
            .await
            .map_err(|e| format!("{function}() call failed: {e}"))?;

        let ledger_str = resp.ledger.map_or("pending".to_string(), |l| l.to_string());
        println!("  {function}() succeeded (ledger: {ledger_str})");
        Ok(())
    }
}

/// Build the ScVal encoding of `SignatureProofs(Map<SignerKey, SignerProof>)`
/// for an ED25519 signer.
///
/// The smart account's `__check_auth` expects `SignatureProofs` which is a
/// `#[contracttype]` tuple struct wrapping `Map<SignerKey, SignerProof>`.
///
/// Soroban `#[contracttype]` encoding rules:
/// - **Named structs** → `ScVal::Map` with `Symbol` field-name keys
/// - **Tuple structs** → `ScVal::Vec` with positional elements
/// - **Enums**         → `ScVal::Vec([Symbol(variant_name), ...fields])`
///
/// So `SignatureProofs(inner_map)` becomes `ScVal::Vec([inner_map_scval])`.
fn build_signature_proofs_scval(public_key: &[u8; 32], signature: &[u8; 64]) -> ScVal {
    // SignerKey::Ed25519(BytesN<32>) → Vec([Symbol("Ed25519"), Bytes(pk)])
    let signer_key = ScVal::Vec(Some(ScVec(
        vec![
            ScVal::Symbol(ScSymbol("Ed25519".try_into().unwrap())),
            ScVal::Bytes(ScBytes(public_key.to_vec().try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    )));

    // SignerProof::Ed25519(BytesN<64>) → Vec([Symbol("Ed25519"), Bytes(sig)])
    let signer_proof = ScVal::Vec(Some(ScVec(
        vec![
            ScVal::Symbol(ScSymbol("Ed25519".try_into().unwrap())),
            ScVal::Bytes(ScBytes(signature.to_vec().try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    )));

    // The inner Map<SignerKey, SignerProof> with one entry
    let inner_map = ScVal::Map(Some(ScMap(
        vec![ScMapEntry {
            key: signer_key,
            val: signer_proof,
        }]
        .try_into()
        .unwrap(),
    )));

    // SignatureProofs is a #[contracttype] TUPLE struct → ScVal::Vec([inner_map])
    ScVal::Vec(Some(ScVec(vec![inner_map].try_into().unwrap())))
}

/// Build the ScVal for `MigrationData::V1ToV2(V1ToV2MigrationData { signers_to_migrate })`.
fn build_migration_data_scval(signers: &DiscoveredSigners) -> ScVal {
    let mut signer_keys = Vec::new();

    for key_id_hex in &signers.secp256r1 {
        let bytes = hex::decode(key_id_hex).expect("invalid hex");
        signer_keys.push(ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Secp256r1".try_into().unwrap())),
                ScVal::Bytes(ScBytes(bytes.try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
        ))));
    }

    for pk_hex in &signers.ed25519 {
        let bytes = hex::decode(pk_hex).expect("invalid hex");
        signer_keys.push(ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Ed25519".try_into().unwrap())),
                ScVal::Bytes(ScBytes(bytes.try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
        ))));
    }

    // V1ToV2MigrationData { signers_to_migrate: Vec<V1SignerKey> }
    // Struct encoding: Map({ Symbol("signers_to_migrate") => Vec([...]) })
    let migration_data_inner = ScVal::Map(Some(ScMap(
        vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol("signers_to_migrate".try_into().unwrap())),
            val: ScVal::Vec(Some(ScVec(signer_keys.try_into().unwrap()))),
        }]
        .try_into()
        .unwrap(),
    )));

    // MigrationData::V1ToV2(inner) - enum encoding: Vec([Symbol("V1ToV2"), inner])
    ScVal::Vec(Some(ScVec(
        vec![
            ScVal::Symbol(ScSymbol("V1ToV2".try_into().unwrap())),
            migration_data_inner,
        ]
        .try_into()
        .unwrap(),
    )))
}

/// Build the ScVal for `BytesN<32>` (used for wasm hash argument).
fn bytes32_to_scval(bytes: &[u8; 32]) -> ScVal {
    ScVal::Bytes(ScBytes(bytes.to_vec().try_into().unwrap()))
}

/// Build the `LedgerKey::ContractData` for an Ed25519 signer's persistent storage entry.
///
/// The smart account stores signers under keys that match the Soroban encoding of
/// `SignerKey::Ed25519(BytesN<32>)`, which is `ScVal::Vec([Symbol("Ed25519"), Bytes(pk)])`.
/// This key lives in the contract's `Persistent` storage.
fn signer_ledger_key(contract_id: &[u8; 32], signer_public_key: &[u8; 32]) -> LedgerKey {
    let signer_key_scval = ScVal::Vec(Some(ScVec(
        vec![
            ScVal::Symbol(ScSymbol("Ed25519".try_into().unwrap())),
            ScVal::Bytes(ScBytes(signer_public_key.to_vec().try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    )));

    LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(*contract_id))),
        key: signer_key_scval,
        durability: ContractDataDurability::Persistent,
    })
}

// =============================================================================
// Auto-discover via stellar CLI (the RPC has no "enumerate all storage" endpoint)
// =============================================================================

/// Auto-discover v1 signer keys by reading persistent storage via the stellar CLI.
///
/// The Soroban RPC's `getLedgerEntries` requires exact keys and cannot enumerate
/// all storage entries. The `stellar contract read` CLI command handles this,
/// so we use it as a fallback for the auto-discover feature.
fn discover_signers(
    contract_id: &str,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<DiscoveredSigners, String> {
    let args = vec![
        "contract".to_string(),
        "read".to_string(),
        "--id".to_string(),
        contract_id.to_string(),
        "--durability".to_string(),
        "persistent".to_string(),
        "--output".to_string(),
        "json".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        "--network-passphrase".to_string(),
        network_passphrase.to_string(),
    ];

    let output = Command::new("stellar")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| {
            format!("Failed to run `stellar contract read` (is stellar CLI installed?): {e}")
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("stellar contract read failed:\n{stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_signer_keys(&stdout)
}

/// Parse the JSON output from `stellar contract read` to extract V1 signer keys.
fn parse_signer_keys(json_output: &str) -> Result<DiscoveredSigners, String> {
    let entries: serde_json::Value =
        serde_json::from_str(json_output).map_err(|e| format!("Failed to parse JSON: {e}"))?;

    let mut signers = DiscoveredSigners::default();

    let arr = entries
        .as_array()
        .ok_or("Expected JSON array from stellar contract read")?;

    for entry in arr {
        let key = match entry.get("key") {
            Some(k) => k,
            None => continue,
        };

        if let Some((variant, hex_bytes)) = extract_signer_variant(key) {
            match variant.as_str() {
                "Ed25519" => {
                    println!("  Discovered Ed25519 signer: {hex_bytes}");
                    signers.ed25519.push(hex_bytes);
                }
                "Secp256r1" => {
                    println!("  Discovered Secp256r1 signer: {hex_bytes}");
                    signers.secp256r1.push(hex_bytes);
                }
                _ => {}
            }
        }
    }

    Ok(signers)
}

/// Try to extract a signer variant name and hex bytes from an ScVal JSON key.
fn extract_signer_variant(key: &serde_json::Value) -> Option<(String, String)> {
    let vec_items = key.get("vec")?.as_array()?;
    if vec_items.len() != 2 {
        return None;
    }
    let symbol = vec_items[0].get("symbol")?.as_str()?;
    let bytes = vec_items[1].get("bytes")?.as_str()?;
    match symbol {
        "Ed25519" | "Secp256r1" => Some((symbol.to_string(), bytes.to_string())),
        _ => None,
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(&cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: &Cli) -> Result<(), String> {
    let client = StellarClient::new(&cli.rpc_url, &cli.source_account, &cli.network_passphrase)?;

    // Verify network connectivity
    let passphrase = client
        .rpc
        .verify_network_passphrase(Some(&cli.network_passphrase))
        .await
        .map_err(|e| format!("Network verification failed: {e}"))?;
    println!("Connected to network: {passphrase}");

    // Resolve contract ID
    let contract_strkey = stellar_strkey::Contract::from_string(&cli.contract_id)
        .map_err(|e| format!("Invalid contract ID: {e}"))?;
    let contract_id: [u8; 32] = contract_strkey.0;

    // Discover or use manually-specified signers for migration
    let signers = if cli.auto_discover {
        println!("[0/3] Auto-discovering signers from on-chain storage...");
        let discovered = discover_signers(&cli.contract_id, &cli.rpc_url, &cli.network_passphrase)?;
        println!(
            "  Found {} Ed25519 signer(s), {} Secp256r1 signer(s)",
            discovered.ed25519.len(),
            discovered.secp256r1.len()
        );
        discovered
    } else {
        DiscoveredSigners {
            ed25519: cli.migrate_ed25519.clone(),
            secp256r1: cli.migrate_secp256r1.clone(),
        }
    };

    // ---- Step 1: Upload v2 WASM (or use provided hash) ----

    let wasm_hash: [u8; 32] = match &cli.wasm_hash {
        Some(hash_hex) => {
            println!("[1/3] Skipping v2 upload — using provided WASM hash: {hash_hex}");
            let bytes = hex::decode(hash_hex).map_err(|e| format!("Invalid wasm hash hex: {e}"))?;
            bytes
                .try_into()
                .map_err(|_| "WASM hash must be 32 bytes".to_string())?
        }
        None => {
            let wasm_path = cli
                .wasm_path
                .as_ref()
                .ok_or("--wasm-path is required when --wasm-hash is not provided")?;
            println!("[1/3] Uploading v2 WASM to the ledger...");
            let wasm = std::fs::read(wasm_path).map_err(|e| format!("Failed to read WASM: {e}"))?;
            if cli.dry_run {
                println!("  [dry-run] Skipping actual upload");
                Sha256::digest(&wasm).into()
            } else {
                client.upload_wasm(&wasm).await?
            }
        }
    };

    // ---- Step 2: Call upgrade(new_wasm_hash) ----

    println!("[2/3] Calling upgrade() on the smart account...");
    let wasm_hash_arg = bytes32_to_scval(&wasm_hash);
    let signer_key = signer_ledger_key(&contract_id, &client.source_public);
    if cli.dry_run {
        println!("  [dry-run] Skipping actual upgrade");
    } else {
        client
            .invoke_contract(
                &contract_id,
                "upgrade",
                vec![wasm_hash_arg],
                vec![signer_key],
            )
            .await?;
    }

    // ---- Step 3: Call migrate(migration_data) ----

    println!("[3/3] Calling migrate() with signer migration data...");
    let migration_data = build_migration_data_scval(&signers);
    let signer_key_migrate = signer_ledger_key(&contract_id, &client.source_public);
    if cli.dry_run {
        println!("  [dry-run] Skipping actual migrate");
    } else {
        client
            .invoke_contract(
                &contract_id,
                "migrate",
                vec![migration_data],
                vec![signer_key_migrate],
            )
            .await?;
    }

    // ---- Summary ----

    println!();
    println!("Upgrade complete!");
    println!("  Contract: {}", cli.contract_id);
    println!("  New WASM: {}", hex::encode(wasm_hash));
    if !signers.secp256r1.is_empty() {
        println!(
            "  Migrated {} Secp256r1 -> Webauthn signer(s)",
            signers.secp256r1.len()
        );
    }
    if !signers.ed25519.is_empty() {
        println!(
            "  Migrated {} Ed25519 signer(s) with policy updates",
            signers.ed25519.len()
        );
    }

    Ok(())
}
