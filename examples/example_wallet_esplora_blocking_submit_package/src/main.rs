#![allow(deprecated)]
use bdk_esplora::{esplora_client as bdk_esplora_client, EsploraExt};
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::OutPoint;
use bdk_wallet::chain::TxUpdate;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::tx_builder;
use bdk_wallet::{
    bitcoin::{Amount, FeeRate, Network},
    psbt::PsbtUtils,
    KeychainKind, SignOptions, Wallet,
};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{collections::BTreeSet, io::Write};

const SEND_AMOUNT: Amount = Amount::from_sat(5000);
const STOP_GAP: usize = 5;
const PARALLEL_REQUESTS: usize = 5;

const DB_PATH: &str = "bdk-example-esplora-blocking-submit-package.sqlite";
const NETWORK: Network = Network::Testnet;
const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";
const ESPLORA_MEMPOOL_SPACE_URL: &str = "https://mempool.space/testnet/api";
const ESPLORA_BLOCKSTREAM_INFO_URL: &str = "https://blockstream.info/testnet/api";

fn main() -> Result<(), anyhow::Error> {
    let mut db = Connection::open(DB_PATH)?;
    let wallet_opt = Wallet::load()
        .descriptor(KeychainKind::External, Some(EXTERNAL_DESC))
        .descriptor(KeychainKind::Internal, Some(INTERNAL_DESC))
        .extract_keys()
        .check_network(NETWORK)
        .load_wallet(&mut db)?;
    let mut wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => Wallet::create(EXTERNAL_DESC, INTERNAL_DESC)
            .network(NETWORK)
            .create_wallet(&mut db)?,
    };

    let address = wallet.next_unused_address(KeychainKind::External);
    wallet.persist(&mut db)?;
    println!(
        "Next unused address: ({}) {}",
        address.index, address.address
    );

    let balance = wallet.balance();
    println!("Wallet balance before syncing: {}", balance.total());

    println!("Full Sync...");
    let bdk_mempool_esplora_client =
        bdk_esplora_client::Builder::new(ESPLORA_MEMPOOL_SPACE_URL).build_blocking();

    let blockstream_esplora_client =
        esplora_client::Builder::new(ESPLORA_BLOCKSTREAM_INFO_URL).build_blocking();

    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = BTreeSet::<KeychainKind>::new();
        move |keychain, spk_i, _| {
            if once.insert(keychain) {
                print!("\nScanning keychain [{keychain:?}] ");
            }
            if spk_i.is_multiple_of(5) {
                print!(" {spk_i:<3}");
            }
            stdout.flush().expect("must flush")
        }
    });

    let update = bdk_mempool_esplora_client.full_scan(request, STOP_GAP, PARALLEL_REQUESTS)?;
    wallet.apply_update(update)?;
    wallet.persist(&mut db)?;
    println!();

    let balance = wallet.balance();
    println!("Wallet balance after syncing: {}", balance.total());

    if balance.total() < SEND_AMOUNT {
        println!("Please send at least {SEND_AMOUNT} to the receiving address");
        std::process::exit(0);
    }

    // create txA with zero fee.
    let mut tx_builder = wallet.build_tx();
    let zero_fee_rate = FeeRate::from_sat_per_vb(0).unwrap();

    tx_builder.add_recipient(address.script_pubkey(), SEND_AMOUNT);
    tx_builder.fee_rate(zero_fee_rate);
    tx_builder.version(3); // it should be v3 for TRUC transactions.

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    assert!(finalized);

    let tx_a = psbt.extract_tx()?;

    println!(
        "txid: {:?}, Raw TxA: {:#?}",
        tx_a.compute_txid(),
        serialize_hex(&tx_a)
    );

    // let original_fee = psbt.fee_amount().unwrap();
    // let tx_feerate = psbt.fee_rate().unwrap();

    let txid_a = tx_a.compute_txid();
    // println!("Tx broadcasted! Txid: https://mempool.space/testnet4/tx/{txid_a}");

    match blockstream_esplora_client.broadcast(&tx_a) {
        Ok(_) => println!("Broadcasting txA (zero-fee) SHOULD NOT succeed"),
        Err(e) => println!("Broadcasting txA (zero-fee) MUST fail: {e}"),
    }

    wallet.apply_unconfirmed_txs(vec![(tx_a.clone(), u64::MAX)]);

    // assert for broadcast failure.

    // create txB that CPFP's txA.
    let mut tx_builder = wallet.build_tx();
    let cpfp_fee_rate = FeeRate::from_sat_per_vb(2).unwrap();

    tx_builder
        .add_utxo(OutPoint::new(txid_a, 0))
        .expect("should not fail");
    tx_builder.manually_selected_only();
    tx_builder.add_recipient(
        address.script_pubkey(),
        SEND_AMOUNT.unchecked_sub(Amount::from_sat(500)),
    );
    tx_builder.fee_rate(cpfp_fee_rate);
    tx_builder.version(3);

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    assert!(finalized);

    let tx_b = psbt.extract_tx()?;
    println!(
        "txid: {:?}, Raw TxB: {:#?}",
        tx_b.compute_txid(),
        serialize_hex(&tx_b)
    );

    let txs_package = vec![tx_a, tx_b];
    match blockstream_esplora_client.submit_package(&txs_package, None, None) {
        Ok(res) => println!("successfully broadcasted package: {res:#?}"),
        Err(e) => println!("failed: {e}"),
    }

    // create a package with txA and txB.
    // broadcast the package through the new esplora-client API.
    // assert for broadcast success.

    // println!("Partial Sync...");
    // print!("SCANNING: ");
    // let mut printed = 0;
    // let sync_request = wallet
    //     .start_sync_with_revealed_spks()
    //     .inspect(move |_, sync_progress| {
    //         let progress_percent =
    //             (100 * sync_progress.consumed()) as f32 / sync_progress.total() as f32;
    //         let progress_percent = progress_percent.round() as u32;
    //         if progress_percent.is_multiple_of(5) && progress_percent > printed {
    //             print!("{progress_percent}% ");
    //             std::io::stdout().flush().expect("must flush");
    //             printed = progress_percent;
    //         }
    //     });
    // let sync_update = client.sync(sync_request, PARALLEL_REQUESTS)?;

    // wallet.apply_update(sync_update)?;
    // wallet.persist(&mut db)?;
    // println!();

    // bump fee rate for tx by at least 1 sat per vbyte
    // let feerate = FeeRate::from_sat_per_vb(tx_feerate.to_sat_per_vb_ceil() + 1).unwrap();
    // let mut builder = wallet.build_fee_bump(txid).unwrap();
    // builder.fee_rate(feerate);
    // let mut new_psbt = builder.finish().unwrap();
    // let finalize_tx = wallet.sign(&mut new_psbt, SignOptions::default())?;
    // assert!(finalize_tx);
    // let new_fee = new_psbt.fee_amount().unwrap();
    // let bumped_tx = new_psbt.extract_tx()?;
    // assert_eq!(
    //     bumped_tx
    //         .output
    //         .iter()
    //         .find(|txout| txout.script_pubkey == address.script_pubkey())
    //         .unwrap()
    //         .value,
    //     SEND_AMOUNT,
    //     "Outputs should remain the same"
    // );
    // assert!(
    //     new_fee > original_fee,
    //     "Replacement tx fee ({new_fee}) should be higher than original ({original_fee})",
    // );

    // wait for first transaction to make it into the mempool and be indexed on mempool.space
    // sleep(Duration::from_secs(10));
    // client.broadcast(&bumped_tx)?;
    // println!(
    //     "Broadcast replacement transaction. Txid: https://mempool.space/testnet4/tx/{}",
    //     bumped_tx.compute_txid()
    // );

    // println!("Syncing after bumped tx...");
    // let sync_request = wallet.start_sync_with_revealed_spks().inspect(|_, _| {});
    // let sync_update = client.sync(sync_request, PARALLEL_REQUESTS)?;
    // println!();

    // let mut evicted_txs = Vec::new();
    // for (txid, last_seen) in &sync_update.tx_update.evicted_ats {
    //     evicted_txs.push((*txid, *last_seen));
    // }

    // wallet.apply_update(sync_update)?;
    // if !evicted_txs.is_empty() {
    //     println!("Applied {} evicted transactions", evicted_txs.len());
    // }
    // wallet.persist(&mut db)?;

    // let balance_after_sync = wallet.balance();
    // println!("Wallet balance after sync: {}", balance_after_sync.total());
    // println!(
    //     "Wallet has {} transactions and {} utxos",
    //     wallet.transactions().count(),
    //     wallet.list_unspent().count()
    // );

    Ok(())
}
