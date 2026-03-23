use anyhow::Context;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::rusqlite;
use bdk_wallet::KeychainKind::{self, External, Internal};
use bdk_wallet::Wallet;

// const DB_PATH: &str = "bdk-example-esplora-async.sqlite";
// const NETWORK: Network = Network::Testnet4;
// const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
// const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

const STOP_GAP: usize = 5;
const PARALLEL_REQUESTS: usize = 5;
const ESPLORA_URL: &str = "https://mempool.space/testnet4/api";

// --8<-- [start:setup]
const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";
const NETWORK: Network = Network::Testnet4;

// path to old pre1 db
const BDK_PRE_V1_DB_PATH: &str = "./bdk-cli-0.27.1/wallet.sqlite";
// path to new db
const BDK_WALLET_DB_PATH: &str = "./bdk-example-migration-from-pre-v1.sqlite";
// --8<-- [end:setup]

// Steps for migrating wallet state from an original `bdk` pre-1.0 version to a new
// `bdk_wallet` 1.0 or greater version.

// To run: change `BDK_DB_PATH` to point to the location of the old database file and
// modify the descriptors and network above to fit your setup. Before running, there
// should not be any persisted data at the new path `BDK_WALLET_DB_PATH`.

// --8<-- [start:main]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --8<-- [start:new]
    // Create new wallet
    let mut db = rusqlite::Connection::open(BDK_WALLET_DB_PATH)?;
    let mut new_wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
        .network(NETWORK)
        .create_wallet(&mut db)
        .context("failed to create wallet")?;
    // --8<-- [end:new]

    // --8<-- [start:pre1]
    // Get new wallet keychain descriptor hashes
    let external_checksum = new_wallet.descriptor_checksum(External);
    let internal_checksum = new_wallet.descriptor_checksum(Internal);

    // Get pre1 wallet keychains and verify checksums match current wallet descriptors
    let mut pre1_db = rusqlite::Connection::open(BDK_PRE_V1_DB_PATH)?;
    let pre1keychains = bdk_wallet::migration::get_pre_v1_wallet_keychains(&mut pre1_db)?;
    assert!(!pre1keychains.is_empty(), "no pre1 keychain found");

    if let Some(pre1_external) = pre1keychains.iter().find(|k| k.keychain == External) {
        assert_eq!(pre1_external.checksum, external_checksum);
        // Restore revealed external keychain to pre1 address index
        let _ = new_wallet
            .reveal_addresses_to(KeychainKind::External, pre1_external.last_derivation_index);
        println!(
            "Found and set pre1 external keychain ({}) last derivation index to {}",
            external_checksum, pre1_external.last_derivation_index
        );
    } else {
        println!("no external pre1 keychain found");
    }

    if let Some(pre1_internal) = pre1keychains.iter().find(|k| k.keychain == Internal) {
        assert_eq!(pre1_internal.checksum.clone(), internal_checksum);
        // Restore revealed internal keychain to pre1 address index
        let _ = new_wallet.reveal_addresses_to(Internal, pre1_internal.last_derivation_index);
        println!(
            "Found and set pre1 internal keychain ({}) last derivation index to {}",
            internal_checksum, pre1_internal.last_derivation_index
        );
    } else {
        println!("no internal pre1 keychain found");
    }
    // --8<-- [end:pre1]

    // --8<-- [start:persist]
    // Persist new wallet
    new_wallet.persist(&mut db)?;
    // --8<-- [end:persist]

    let balance = new_wallet.balance();
    println!("Wallet balance before syncing: {}", balance.total());

    println!("Full Sync...");
    let client = bdk_esplora::esplora_client::Builder::new(ESPLORA_URL).build_async()?;

    let request = new_wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = std::collections::BTreeSet::<KeychainKind>::new();
        move |keychain, spk_i, _| {
            if once.insert(keychain) {
                print!("\nScanning keychain [{keychain:?}]");
            }
            print!(" {spk_i:<3}");
            std::io::Write::flush(&mut stdout).expect("must flush")
        }
    });

    let update = bdk_esplora::EsploraAsyncExt::full_scan(&client, request, STOP_GAP, PARALLEL_REQUESTS)
        .await?;

    new_wallet.apply_update(update)?;
    new_wallet.persist(&mut db)?;
    println!();

    let balance = new_wallet.balance();
    println!("Wallet balance after full sync: {}", balance.total());
    println!(
        "Wallet has {} transactions and {} utxos after full sync",
        new_wallet.transactions().count(),
        new_wallet.list_unspent().count()
    );

    Ok(())
}
// --8<-- [end:main]