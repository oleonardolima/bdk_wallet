#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, VecDeque};

use bdk_wallet::{bitcoin::Network, chain::TxUpdate, CreateParams, KeychainKind, Update, Wallet};
use bdk_wallet_fuzz::utils::*;

// testnet descriptors
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

// mainnet descriptors
// const INTERNAL_DESCRIPTOR: &str = "wpkh(xprv9y5m1SxNcjAY8DJPHqXM67ETRFwpjsacG9xGBiTBMj5A2KupsjuNJuFuFJAzoQJb7fjp3jz78TsmDmqpaTtCBzAKEuqE1NMC3Net5Ma2hY6/84'/1'/0'/0/*)";
// const EXTERNAL_DESCRIPTOR: &str = "wpkh(xprv9y5m1SxNcjAY8DJPHqXM67ETRFwpjsacG9xGBiTBMj5A2KupsjuNJuFuFJAzoQJb7fjp3jz78TsmDmqpaTtCBzAKEuqE1NMC3Net5Ma2hY6/84'/1'/0'/1/*)";

// testnet
const NETWORK: Network = Network::Testnet;

// mainnet
// const NETWORK = Network::Testnet;

fuzz_target!(|data: &[u8]| {
    // let data_iter = data.iter();
    let params = CreateParams::new(INTERNAL_DESCRIPTOR, EXTERNAL_DESCRIPTOR).network(NETWORK);
    let mut wallet = match Wallet::create_with_params(params) {
        Ok(wallet) => wallet,
        Err(_) => panic!(),
    };

    let mut unconfirmed_txids = VecDeque::new();

    // fuzzed code goes here

    // fuzz test wallet updates

    // start with active indices.
    let mut last_active_indices = BTreeMap::new();
    last_active_indices.extend(get_last_active_indices(data, KeychainKind::Internal));
    last_active_indices.extend(get_last_active_indices(data, KeychainKind::External));

    // generate the txs for the tx graph
    let txs = get_txs(data, &mut wallet);
    let _ = txs
        .iter()
        .map(|tx| unconfirmed_txids.push_back(tx.compute_txid()));

    let txouts = get_txouts(data);

    let anchors = get_anchors(data, unconfirmed_txids.clone());
    // if let Some(txid) = unconfirmed_txids.pop_front() {
    //     anchors.insert((anchor, txid));
    // };

    let seen_ats = get_seen_ats(data, unconfirmed_txids.clone());
    let evicted_ats = get_evicted_ats(data, unconfirmed_txids);

    // build the tx update with fuzzed data
    let mut tx_update = TxUpdate::default();
    tx_update.txs = txs;
    tx_update.txouts = txouts;
    tx_update.anchors = anchors;
    tx_update.seen_ats = seen_ats;
    tx_update.evicted_ats = evicted_ats;

    // generate the chain/checkpoints

    let chain = get_checkpoint(data);

    let update = Update {
        last_active_indices,
        tx_update: tx_update,
        chain: chain,
    };

    match wallet.apply_update(update.clone()) {
        Ok(_result) => {
            // println!("{:#?}", update);
            // println!("successfully updated wallet")
        }
        Err(e) => {
            // println!("{:#?}", update)
        }
    };
});

//     let txouts_count = *next_or_return!(data_iter) as usize;
//     let mut txouts = BTreeMap::new();
//     for _ in 0..txouts_count {
//         let outpoint = bitcoin::OutPoint::new(
//             unique_hash.get_txid(),
//             *next_or_return!(data_iter) as u32,
//         );
//         let amount = *next_or_return!(data_iter) as u64 * 1_000;
//         let value = bitcoin::Amount::from_sat(amount);
//         txouts.insert(
//             outpoint,
//             bitcoin::TxOut {
//                 value,
//                 script_pubkey: Default::default(),
//             },
//         );
//     }

//     let mut anchors = BTreeSet::new();
//     while next_or_return!(data_iter) & 0x01 == 0x01 {
//         let height = scale(*next_or_return!(data_iter));
//         let hash = unique_hash.get_block_hash();
//         let block_id = BlockId { height, hash };
//         let confirmation_time = scale_u64(*next_or_return!(data_iter));
//         let anchor = ConfirmationBlockTime {
//             block_id,
//             confirmation_time,
//         };
//         // FIXME: inserting anchors for transactions not in the tx graph will fail the
//         // SQLite persistence.
//         //let txid = unconfirmed_txids
//         //.pop_front()
//         //.unwrap_or(unique_hash.get_txid());
//         if let Some(txid) = unconfirmed_txids.pop_front() {
//             anchors.insert((anchor, txid));
//         } else {
//             break;
//         }
//     }

//     let mut seen_ats = HashMap::new();
//     while next_or_return!(data_iter) & 0x01 == 0x01 {
//         let time = cmp::min(scale_u64(*next_or_return!(data_iter)), i64::MAX as u64 - 1);
//         let txid = unconfirmed_txids
//             .pop_front()
//             .unwrap_or(unique_hash.get_txid());
//         seen_ats.insert(txid, time);
//     }

//     let tx_update = TxUpdate {
//         txs,
//         txouts,
//         anchors,
//         seen_ats,
//     };

//     // Finally, do the chain update.
//     // TODO: sometimes generate invalid updates, reorgs, etc.
//     let chain = if next_or_return!(data_iter) & 0x01 == 0x01 {
//         let mut tip = wallet.latest_checkpoint();
//         let tip_height = tip.height();
//         let blocks_count = *next_or_return!(data_iter) as u32;
//         for i in 1..blocks_count + 1 {
//             tip = tip
//                 .push(BlockId {
//                     height: tip_height + i,
//                     hash: unique_hash.get_block_hash(),
//                 })
//                 .unwrap();
//         }
//         Some(tip)
//     } else {
//         None
//     };

//     // The Wallet update should never fail as we only ever create a consistent chain.
//     let update = WalletUpdate {
//         last_active_indices,
//         tx_update,
//         chain,
//     };
//     wallet.apply_update(update).unwrap();
// }
// // Assert the wallet roundtrips to persistence and check some invariants.
