use bdk_electrum::electrum_client;
use bdk_electrum::electrum_client::Config;
use bdk_electrum::electrum_client::ElectrumApi;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::Amount;
use bdk_wallet::bitcoin::FeeRate;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::chain::collections::HashSet;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::tx_builder;
use bdk_wallet::Wallet;
use bdk_wallet::{KeychainKind, SignOptions};
use bitcoin::consensus::encode::serialize_hex;
use std::io::Write;
use std::ops::Sub;
use std::thread::sleep;
use std::time::Duration;

const SEND_AMOUNT: Amount = Amount::from_sat(5000);
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

const DB_PATH: &str = "bdk-example-electrum-submit-package.sqlite";
const NETWORK: Network = Network::Testnet;
const EXTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const INTERNAL_DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";
const ELECTRUM_URL: &str = "ssl://testnet.qtornado.com:51002";

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
    println!("Generated Address: {address}");

    let balance = wallet.balance();
    println!("Wallet balance before syncing: {}", balance.total());

    println!("Performing Full Sync...");
    let client = BdkElectrumClient::new(electrum_client::Client::from_config(
        ELECTRUM_URL,
        Config::builder().validate_domain(false).build(),
    )?);

    // Populate the electrum client's transaction cache so it doesn't redownload transaction we
    // already have.
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = HashSet::<KeychainKind>::new();
        move |k, spk_i, _| {
            if once.insert(k) {
                print!("\nScanning keychain [{k:?}]");
            }
            print!(" {spk_i:<3}");
            stdout.flush().expect("must flush");
        }
    });

    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)?;

    println!();

    wallet.apply_update(update)?;
    wallet.persist(&mut db)?;

    let balance = wallet.balance();
    println!("Wallet balance after full sync: {}", balance.total());
    println!(
        "Wallet has {} transactions and {} utxos after full sync",
        wallet.transactions().count(),
        wallet.list_unspent().count()
    );

    if balance.total() < SEND_AMOUNT {
        println!("Please send at least {SEND_AMOUNT} to the receiving address");
        std::process::exit(0);
    }

    // steps required to test the new submit packages method:
    //  create txA - zero fee.
    //  attempt to broadcast txA, should get a broadcast failure.
    //  create txB - CPFP for txA.
    //  build a transaction package of txA and txB.
    //  broadcasts the (txA, txB) transaction package.

    // create txA, a zero-fee transaction.
    let zero_fee =
        FeeRate::from_sat_per_vb(0).expect("should successfully create a zero-fee `FeeRate`");

    let mut tx_builder = wallet.build_tx();

    tx_builder.add_recipient(address.script_pubkey(), SEND_AMOUNT);
    tx_builder.version(3); // NOTE: it's mandatory being a V3 for TRUC txs.
    tx_builder.fee_rate(zero_fee);

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    assert!(
        finalized,
        "should've successfully created and finalized (zero-fee) txA"
    );

    let tx_a = psbt.extract_tx()?;

    println!(
        "zero-fee txA ;\n txid = {:?} ;\n raw txA = {:#?}",
        tx_a.compute_txid(),
        serialize_hex(&tx_a)
    );

    // attempt txA broadcast, assert broadcast failure.
    match client.transaction_broadcast(&tx_a) {
        Ok(_) => panic!("the broadcast of (zero-fee) txA SHOULD NOT succeed"),
        Err(e) => println!("the broadcast of (zero-fee) txA FAILED, as expected: {e}"),
    }

    // applies the not broadcasted txA, so it's available on tx_graph when creating the txB.
    wallet.apply_unconfirmed_txs(vec![(tx_a.clone(), u64::MAX)]);

    // create txB, a CPFP for txA.
    let mut tx_builder = wallet.build_tx();
    let cpfp_fee_rate =
        FeeRate::from_sat_per_vb(2).expect("should successfully create a `FeeRate` of 2 sat/vb");

    tx_builder.manually_selected_only();
    tx_builder
        .add_utxo(bitcoin::OutPoint {
            txid: tx_a.compute_txid(),
            vout: 0,
        })
        .expect("should add the txA UTXO that MUST be spent successfully!");

    tx_builder.fee_rate(cpfp_fee_rate);
    tx_builder.version(3); // NOTE: it's mandatory being a V3 for TRUC txs.
    tx_builder.add_recipient(
        address.script_pubkey(),
        SEND_AMOUNT.sub(Amount::from_sat(500)),
    );

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    assert!(
        finalized,
        "should've successfully created and finalized (CPFP) txB"
    );

    let tx_b = psbt.extract_tx()?;

    println!(
        "CPFP txB ;\n txid = {:?} ;\n raw txB = {:#?}",
        tx_b.compute_txid(),
        serialize_hex(&tx_b)
    );

    // // attempt txA broadcast, assert broadcast failure.
    // match client.transaction_broadcast(&tx_a) {
    //     Ok(_) => panic!("the broadcast of (zero-fee) txA SHOULD NOT succeed"),
    //     Err(e) => println!("the broadcast of (zero-fee) txA FAILED, as expected: {e}"),
    // }

    let tx_package = vec![tx_a, tx_b];
    match client.inner.transaction_broadcast_package(&tx_package) {
        Ok(res) => {
            println!("the broadcast of tx package of txA + txB SHOULD SUCCEED! {res:?}")
        }
        Err(e) => panic!("the broadcast of tx package (txA + txB) FAILED! {e}"),
    }

    // let target_fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
    // let mut tx_builder = wallet.build_tx();
    // tx_builder.add_recipient(address.script_pubkey(), SEND_AMOUNT);
    // tx_builder.fee_rate(target_fee_rate);

    // let mut psbt = tx_builder.finish()?;
    // let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    // assert!(finalized);
    // let original_fee = psbt.fee_amount().unwrap();
    // let tx_feerate = psbt.fee_rate().unwrap();
    // let tx = psbt.extract_tx()?;
    // client.transaction_broadcast(&tx)?;
    // let txid = tx.compute_txid();
    // println!("Tx broadcasted! Txid: https://mempool.space/testnet/tx/{txid}");

    // println!("Partial Sync...");
    // print!("SCANNING: ");
    // let mut last_printed = 0;
    // let sync_request = wallet
    //     .start_sync_with_revealed_spks()
    //     .inspect(move |_, sync_progress| {
    //         let progress_percent =
    //             (100 * sync_progress.consumed()) as f32 / sync_progress.total() as f32;
    //         let progress_percent = progress_percent.round() as u32;
    //         if progress_percent % 5 == 0 && progress_percent > last_printed {
    //             print!("{progress_percent}% ");
    //             std::io::stdout().flush().expect("must flush");
    //             last_printed = progress_percent;
    //         }
    //     });
    // client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));
    // let sync_update = client.sync(sync_request, BATCH_SIZE, false)?;
    // println!();
    // wallet.apply_update(sync_update)?;
    // wallet.persist(&mut db)?;

    // // bump fee rate for tx by at least 1 sat per vbyte
    // let feerate = FeeRate::from_sat_per_vb(tx_feerate.to_sat_per_vb_ceil() + 1).unwrap();
    // let mut builder = wallet.build_fee_bump(txid).expect("failed to bump tx");
    // builder.fee_rate(feerate);
    // let mut bumped_psbt = builder.finish().unwrap();
    // let finalize_btx = wallet.sign(&mut bumped_psbt, SignOptions::default())?;
    // assert!(finalize_btx);
    // let new_fee = bumped_psbt.fee_amount().unwrap();
    // let bumped_tx = bumped_psbt.extract_tx()?;
    // assert_eq!(
    //     bumped_tx
    //         .output
    //         .iter()
    //         .find(|txout| txout.script_pubkey == address.script_pubkey())
    //         .unwrap()
    //         .value,
    //     SEND_AMOUNT,
    //     "Recipient output should remain unchanged"
    // );
    // assert!(
    //     new_fee > original_fee,
    //     "New fee ({new_fee}) should be higher than original ({original_fee})"
    // );

    // // wait for first transaction to make it into the mempool and be indexed on mempool.space
    // sleep(Duration::from_secs(10));
    // client.transaction_broadcast(&bumped_tx)?;
    // println!(
    //     "Broadcasted bumped tx. Txid: https://mempool.space/testnet4/tx/{}",
    //     bumped_tx.compute_txid()
    // );

    println!("Syncing after bumped tx broadcast...");
    let sync_request = wallet.start_sync_with_revealed_spks().inspect(|_, _| {});
    let sync_update = client.sync(sync_request, BATCH_SIZE, false)?;

    let mut evicted_txs = Vec::new();
    for (txid, last_seen) in &sync_update.tx_update.evicted_ats {
        evicted_txs.push((*txid, *last_seen));
    }

    wallet.apply_update(sync_update)?;
    if !evicted_txs.is_empty() {
        println!("Applied {} evicted transactions", evicted_txs.len());
    }
    wallet.persist(&mut db)?;

    let balance_after_sync = wallet.balance();
    println!("Wallet balance after sync: {}", balance_after_sync.total());
    println!(
        "Wallet has {} transactions and {} utxos after partial sync",
        wallet.transactions().count(),
        wallet.list_unspent().count()
    );

    Ok(())
}
