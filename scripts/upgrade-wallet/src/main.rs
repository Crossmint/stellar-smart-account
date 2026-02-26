//! CLI tool for upgrading a v1.0.0 Smart Account to v2.
//!
//! This script orchestrates the two-phase upgrade process:
//! 1. Upload the v2 WASM binary to the ledger
//! 2. Call `upgrade(new_wasm_hash)` on the smart account
//! 3. Call `migrate(migration_data)` with the list of signers to migrate
//!
//! It wraps the `stellar` CLI, which must be installed and available in PATH.
//!
//! # Usage
//!
//! ```bash
//! # Auto-discover signers from on-chain storage (recommended)
//! upgrade-wallet \
//!   --rpc-url https://soroban-testnet.stellar.org \
//!   --network-passphrase "Test SDF Network ; September 2015" \
//!   --source-account SC...SECRET \
//!   --contract-id CA...ADDR \
//!   --wasm-path ./target/wasm32v1-none/release/smart_account.wasm \
//!   --auto-discover
//!
//! # Upgrade with no signers to migrate (Ed25519-only account)
//! upgrade-wallet \
//!   --rpc-url https://soroban-testnet.stellar.org \
//!   --network-passphrase "Test SDF Network ; September 2015" \
//!   --source-account SC...SECRET \
//!   --contract-id CA...ADDR \
//!   --wasm-path ./target/wasm32v1-none/release/smart_account.wasm
//!
//! # Upgrade with manual signer specification
//! upgrade-wallet \
//!   --rpc-url https://soroban-testnet.stellar.org \
//!   --network-passphrase "Test SDF Network ; September 2015" \
//!   --source-account SC...SECRET \
//!   --contract-id CA...ADDR \
//!   --wasm-path ./smart_account_v2.wasm \
//!   --migrate-secp256r1 "key_id_hex_1,key_id_hex_2" \
//!   --migrate-ed25519 "pubkey_hex_1"
//! ```

use clap::Parser;
use std::process::{Command, Stdio};

/// CLI tool for upgrading a v1 Smart Account wallet to v2 via Stellar RPC.
///
/// Requires the `stellar` CLI to be installed and in PATH.
#[derive(Parser, Debug)]
#[command(name = "upgrade-wallet")]
#[command(about = "Upgrade a v1.0.0 Smart Account to v2 with optional data migration")]
struct Cli {
    /// RPC server endpoint (e.g. https://soroban-testnet.stellar.org).
    /// Not required when --network is provided.
    #[arg(long, env = "STELLAR_RPC_URL", required_unless_present = "network")]
    rpc_url: Option<String>,

    /// Network passphrase (e.g. "Test SDF Network ; September 2015").
    /// Not required when --network is provided.
    #[arg(long, env = "STELLAR_NETWORK_PASSPHRASE", required_unless_present = "network")]
    network_passphrase: Option<String>,

    /// Source account secret key (SC...) or identity name
    #[arg(long, env = "STELLAR_ACCOUNT")]
    source_account: String,

    /// The smart account contract address to upgrade (CA...)
    #[arg(long)]
    contract_id: String,

    /// Path to the v2 WASM binary
    #[arg(long)]
    wasm_path: String,

    /// Auto-discover signers from on-chain contract storage via RPC.
    /// Reads all persistent storage entries and identifies v1 signer keys.
    #[arg(long, default_value_t = false)]
    auto_discover: bool,

    /// Hex-encoded key_id values of Secp256r1 signers to migrate to Webauthn
    /// (comma-separated). These are the WebAuthn credential IDs from v1.
    #[arg(long, value_delimiter = ',')]
    migrate_secp256r1: Vec<String>,

    /// Hex-encoded public keys of Ed25519 signers that need policy migration
    /// (e.g. signers with TimeWindowPolicy). Comma-separated.
    #[arg(long, value_delimiter = ',')]
    migrate_ed25519: Vec<String>,

    /// Skip the upload step if the WASM is already on the ledger.
    /// Provide the wasm hash directly.
    #[arg(long)]
    wasm_hash: Option<String>,

    /// Perform a dry-run: simulate only, don't submit transactions.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Network name shortcut (e.g. "testnet", "mainnet"). Overrides
    /// --rpc-url and --network-passphrase if the stellar CLI has it configured.
    #[arg(long, short)]
    network: Option<String>,
}

/// Holds the discovered signer keys for migration.
#[derive(Debug, Default)]
struct DiscoveredSigners {
    ed25519: Vec<String>,
    secp256r1: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(&cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    check_stellar_cli()?;

    // Determine signers: auto-discover from RPC or use CLI-provided lists
    let signers = if cli.auto_discover {
        println!("[0/3] Auto-discovering signers from on-chain storage...");
        let discovered = discover_signers(cli)?;
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

    // Step 1: Upload WASM (or use provided hash)
    let wasm_hash = match &cli.wasm_hash {
        Some(hash) => {
            println!("[1/3] Skipping upload — using provided WASM hash: {hash}");
            hash.clone()
        }
        None => {
            println!("[1/3] Uploading v2 WASM to the ledger...");
            upload_wasm(cli)?
        }
    };

    // Step 2: Call upgrade(new_wasm_hash)
    println!("[2/3] Calling upgrade() on the smart account...");
    call_upgrade(cli, &wasm_hash)?;

    // Step 3: Call migrate(migration_data)
    println!("[3/3] Calling migrate() with signer migration data...");
    call_migrate(cli, &signers)?;

    println!();
    println!("Upgrade complete!");
    println!("  Contract: {}", cli.contract_id);
    println!("  New WASM: {wasm_hash}");
    if !signers.secp256r1.is_empty() {
        println!(
            "  Migrated {} Secp256r1 → Webauthn signer(s)",
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

/// Verify the `stellar` CLI is available.
fn check_stellar_cli() -> Result<(), String> {
    Command::new("stellar")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Failed to run `stellar` CLI. Is it installed? Error: {e}"))?;
    Ok(())
}

/// Build CLI args for network connection only (no source-account).
/// Used for read-only RPC operations like `stellar contract read`.
fn network_args(cli: &Cli) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(network) = &cli.network {
        args.extend(["--network".to_string(), network.clone()]);
    } else {
        // Safe to unwrap: clap requires these when --network is absent
        args.extend([
            "--rpc-url".to_string(),
            cli.rpc_url.clone().unwrap(),
            "--network-passphrase".to_string(),
            cli.network_passphrase.clone().unwrap(),
        ]);
    }

    args
}

/// Build the common CLI args for RPC connection including source account.
/// Used for write operations (upload, invoke).
fn rpc_args(cli: &Cli) -> Vec<String> {
    let mut args = network_args(cli);
    args.extend([
        "--source-account".to_string(),
        cli.source_account.clone(),
    ]);
    args
}

/// Auto-discover v1 signer keys by reading all persistent storage from the contract.
///
/// Uses `stellar contract read --durability persistent --output json` to fetch all
/// persistent storage entries, then parses the JSON to identify V1SignerKey entries.
///
/// Soroban `#[contracttype]` enums are encoded as ScVal::Vec where the first element
/// is a Symbol with the variant name:
///   V1SignerKey::Ed25519(BytesN<32>)  → {"vec": [{"symbol": "Ed25519"}, {"bytes": "..."}]}
///   V1SignerKey::Secp256r1(Bytes)     → {"vec": [{"symbol": "Secp256r1"}, {"bytes": "..."}]}
fn discover_signers(cli: &Cli) -> Result<DiscoveredSigners, String> {
    let mut args = vec![
        "contract".to_string(),
        "read".to_string(),
        "--id".to_string(),
        cli.contract_id.clone(),
        "--durability".to_string(),
        "persistent".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    args.extend(network_args(cli));

    let output = Command::new("stellar")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute stellar contract read: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("stellar contract read failed:\n{stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_signer_keys(&stdout)
}

/// Parse the JSON output from `stellar contract read` to extract V1 signer keys.
///
/// The output is a JSON array of ledger entries. Each entry has a "key" field
/// containing the ScVal-encoded storage key. We look for entries whose key
/// matches the V1SignerKey enum pattern (a vec with a symbol variant name).
fn parse_signer_keys(json_output: &str) -> Result<DiscoveredSigners, String> {
    let entries: serde_json::Value =
        serde_json::from_str(json_output).map_err(|e| format!("Failed to parse JSON: {e}"))?;

    let mut signers = DiscoveredSigners::default();

    let arr = entries
        .as_array()
        .ok_or("Expected JSON array from stellar contract read")?;

    for entry in arr {
        // Each entry has "key" and "value" fields
        let key = match entry.get("key") {
            Some(k) => k,
            None => continue,
        };

        // Try to extract a signer key from this entry's key
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
                _ => {} // Skip unknown variants (e.g. Webauthn, Multisig from v2)
            }
        }
    }

    Ok(signers)
}

/// Try to extract a signer variant name and hex bytes from an ScVal JSON key.
///
/// Soroban enums are encoded as:
///   {"vec": [{"symbol": "VariantName"}, {"bytes": "hex_value"}]}
///
/// Returns Some((variant_name, hex_bytes)) if the key matches this pattern
/// with a recognized signer variant name.
fn extract_signer_variant(key: &serde_json::Value) -> Option<(String, String)> {
    let vec_items = key.get("vec")?.as_array()?;

    // Signer keys have exactly 2 elements: symbol + bytes
    if vec_items.len() != 2 {
        return None;
    }

    let symbol = vec_items[0].get("symbol")?.as_str()?;
    let bytes = vec_items[1].get("bytes")?.as_str()?;

    // Only match known v1 signer key variant names
    match symbol {
        "Ed25519" | "Secp256r1" => Some((symbol.to_string(), bytes.to_string())),
        _ => None,
    }
}

/// Upload the WASM binary and return its hash.
fn upload_wasm(cli: &Cli) -> Result<String, String> {
    let mut args = vec![
        "contract".to_string(),
        "upload".to_string(),
        "--wasm".to_string(),
        cli.wasm_path.clone(),
    ];
    args.extend(rpc_args(cli));

    if cli.dry_run {
        args.push("--sim-only".to_string());
    }

    let output = Command::new("stellar")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute stellar contract upload: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("WASM upload failed:\n{stderr}"));
    }

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("  WASM hash: {hash}");
    Ok(hash)
}

/// Call upgrade(new_wasm_hash) on the smart account contract.
fn call_upgrade(cli: &Cli, wasm_hash: &str) -> Result<(), String> {
    let mut args = vec![
        "contract".to_string(),
        "invoke".to_string(),
        "--id".to_string(),
        cli.contract_id.clone(),
    ];
    args.extend(rpc_args(cli));

    if cli.dry_run {
        args.push("--sim-only".to_string());
    }

    // The -- separator tells stellar CLI that what follows are the contract function args
    args.extend([
        "--".to_string(),
        "upgrade".to_string(),
        "--new_wasm_hash".to_string(),
        wasm_hash.to_string(),
    ]);

    let output = Command::new("stellar")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute upgrade: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("upgrade() call failed:\n{stderr}"));
    }

    println!("  upgrade() succeeded");
    Ok(())
}

/// Call migrate(migration_data) on the smart account contract.
///
/// The migration_data is a `MigrationData` enum variant serialized as JSON
/// for the stellar CLI's `--arg` passing.
fn call_migrate(cli: &Cli, signers: &DiscoveredSigners) -> Result<(), String> {
    let mut args = vec![
        "contract".to_string(),
        "invoke".to_string(),
        "--id".to_string(),
        cli.contract_id.clone(),
    ];
    args.extend(rpc_args(cli));

    if cli.dry_run {
        args.push("--sim-only".to_string());
    }

    let migration_data_json = build_migration_data_json(signers);

    args.extend([
        "--".to_string(),
        "migrate".to_string(),
        "--migration_data".to_string(),
        migration_data_json,
    ]);

    let output = Command::new("stellar")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute migrate: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("migrate() call failed:\n{stderr}"));
    }

    println!("  migrate() succeeded");
    Ok(())
}

/// Build the JSON representation of MigrationData for the stellar CLI.
///
/// The stellar CLI can accept contract type arguments as JSON. The format for
/// Soroban enum variants in JSON is: `{"VariantName": inner_value}`.
///
/// The migrate() function accepts a `MigrationData` enum, currently with a single
/// variant `V1ToV2(V1ToV2MigrationData)`. The JSON encoding is:
///   {"V1ToV2": {"signers_to_migrate": [...]}}
fn build_migration_data_json(signers: &DiscoveredSigners) -> String {
    let mut signer_keys: Vec<serde_json::Value> = Vec::new();

    // Add Secp256r1 signer keys (key_id bytes in hex)
    for key_id_hex in &signers.secp256r1 {
        signer_keys.push(serde_json::json!({
            "Secp256r1": key_id_hex
        }));
    }

    // Add Ed25519 signer keys (public key bytes in hex)
    for pk_hex in &signers.ed25519 {
        signer_keys.push(serde_json::json!({
            "Ed25519": pk_hex
        }));
    }

    // Wrap in the MigrationData::V1ToV2 enum variant
    let migration_data = serde_json::json!({
        "V1ToV2": {
            "signers_to_migrate": signer_keys
        }
    });

    serde_json::to_string(&migration_data).expect("JSON serialization cannot fail")
}
