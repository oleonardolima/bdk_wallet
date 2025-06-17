#![no_main]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bdk_wallet::{
    bitcoin::{self, hashes::Hash, Network, OutPoint, Transaction, TxOut},
    chain::{BlockId, ConfirmationBlockTime, TxUpdate},
    CreateParams, KeychainKind, Update, Wallet,
};
use libfuzzer_sys::fuzz_target;

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

macro_rules! next_or_return {
    ($iter:expr) => {
        match $iter.next() {
            Some(val) => val,
            None => return,
        }
    };
}

fn scale(byte: u8) -> u32 {
    (byte as u32) * 0x01000000
}

fn scale_u64(byte: u8) -> u64 {
    (byte as u64) * 0x0100000000000000
}

struct UniqueHash {
    data: [u8; 32],
}

impl UniqueHash {
    pub fn new() -> Self {
        Self { data: [0; 32] }
    }

    pub fn get(&mut self) -> [u8; 32] {
        for byte in self.data.iter_mut().rev() {
            if *byte < u8::MAX {
                *byte += 1;
                break;
            }
        }
        self.data
    }

    pub fn get_block_hash(&mut self) -> bitcoin::BlockHash {
        bitcoin::hash_types::BlockHash::from_byte_array(self.get())
    }

    pub fn get_txid(&mut self) -> bitcoin::Txid {
        bitcoin::hash_types::Txid::from_byte_array(self.get())
    }
}

fn get_last_active_indices(data: &[u8], keychain: KeychainKind) -> BTreeMap<KeychainKind, u32> {
    let data_iter = data.iter();
    let mut last_active_indices = BTreeMap::new();
    if next_or_return!(data_iter) & 0x01 == 0x01 {
        let index_count = *next_or_return!(data_iter) as u32;
        let index_start = scale(*next_or_return!(data_iter));
        let res: BTreeMap<KeychainKind, u32> = (index_start..index_count)
            .map(|idx| (keychain, idx))
            .collect();
        last_active_indices.extend(res);
    }
    last_active_indices
}

// TODO: (@oleonardoliam) add more edge cases, eg coinbase txs.
fn get_txs(data: &[u8], wallet: Wallet) -> Vec<Transaction> {
    let data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

    let txs_count = *next_or_return!(data_iter) as usize;
    let mut txs = Vec::with_capacity(txs_count);
    for _ in 0..txs_count {
        let version = scale(*next_or_return!(data_iter)) as i32;
        // FIXME: should we use the consensus decode
        let version = bitcoin::transaction::Version(version);

        let lock_time = scale(*next_or_return!(data_iter));
        let lock_time = bitcoin::absolute::LockTime::from_consensus(lock_time);

        let txin_count = *next_or_return!(data_iter) as usize;
        let mut input = Vec::with_capacity(txin_count);
        for _ in 0..txin_count {
            let previous_output =
                bitcoin::OutPoint::new(unique_hash.get_txid(), *next_or_return!(data_iter) as u32);
            input.push(bitcoin::TxIn {
                previous_output,
                ..Default::default()
            });
        }
        let txout_count = *next_or_return!(data_iter) as usize;
        let mut output = Vec::with_capacity(txout_count);
        for _ in 0..txout_count {
            let script_pubkey = if next_or_return!(data_iter) & 0x01 == 0x01 {
                wallet
                    .next_unused_address(KeychainKind::External)
                    .script_pubkey()
            } else if next_or_return!(data_iter) & 0x01 == 0x01 {
                wallet
                    .next_unused_address(KeychainKind::Internal)
                    .script_pubkey()
            } else {
                bitcoin::ScriptBuf::from_bytes(unique_hash.get().into())
            };
            let amount = *next_or_return!(data_iter) as u64 * 1_000;
            let value = bitcoin::Amount::from_sat(amount);
            output.push(bitcoin::TxOut {
                value,
                script_pubkey,
            });
        }
        let tx = bitcoin::Transaction {
            version,
            lock_time,
            input,
            output,
        };
        txs.push(tx.into());
    }
    txs
}

fn get_txouts(data: &[u8]) -> BTreeMap<OutPoint, TxOut> {
    let mut data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

    let txouts_count = *next_or_return!(data_iter) as usize;
    let mut txouts = BTreeMap::new();
    for _ in 0..txouts_count {
        let outpoint =
            bitcoin::OutPoint::new(unique_hash.get_txid(), *next_or_return!(data_iter) as u32);
        let amount = *next_or_return!(data_iter) as u64 * 1_000;
        let value = bitcoin::Amount::from_sat(amount);
        txouts.insert(
            outpoint,
            bitcoin::TxOut {
                value,
                script_pubkey: Default::default(),
            },
        );
    }
    txouts
}

fn get_anchors(data: &[u8]) {
    let data_iter = data.iter();
    let unique_hash = UniqueHash::new();

    let mut anchors = BTreeSet::new();
    while next_or_return!(data_iter) & 0x01 == 0x01 {
        let height = scale(*next_or_return!(data_iter));
        let hash = unique_hash.get_block_hash();
        let block_id = BlockId { height, hash };
        let confirmation_time = scale_u64(*next_or_return!(data_iter));
        let anchor = ConfirmationBlockTime {
            block_id,
            confirmation_time,
        };
        // FIXME: inserting anchors for transactions not in the tx graph will fail the
        // SQLite persistence.
        //let txid = unconfirmed_txids
        //.pop_front()
        //.unwrap_or(unique_hash.get_txid());
    }
    anchors
}

fuzz_target!(|data: &[u8]| {
    // let data_iter = data.iter();
    let params = CreateParams::new(INTERNAL_DESCRIPTOR, EXTERNAL_DESCRIPTOR);
    let wallet = match Wallet::create_with_params(params) {
        Ok(wallet) => wallet,
        Err(_) => return,
    };

    let mut unconfirmed_txids = VecDeque::new();

    // fuzzed code goes here

    // fuzz test wallet updates

    //     // The Wallet update should never fail as we only ever create a consistent chain.
    // let update = WalletUpdate {
    //     last_active_indices,
    //     tx_update,
    //     chain,
    // };
    // wallet.apply_update(update).unwrap();

    // start with active indices.
    let mut last_active_indices = BTreeMap::new();
    last_active_indices.extend(get_last_active_indices(data, KeychainKind::Internal));
    last_active_indices.extend(get_last_active_indices(data, KeychainKind::External));

    // generate the txs for the tx graph
    let txs = get_txs(data, wallet);
    txs.iter()
        .map(|tx| unconfirmed_txids.push_back(tx.compute_txid()));

    let txouts = get_txouts(data);

    let mut anchors = get_anchors(data);
    if let Some(txid) = unconfirmed_txids.pop_front() {
        anchors.insert((anchor, txid));
    };

    let mut seen_ats = HashMap::new();
    while next_or_return!(data_iter) & 0x01 == 0x01 {
        let time = cmp::min(scale_u64(*next_or_return!(data_iter)), i64::MAX as u64 - 1);
        let txid = unconfirmed_txids
            .pop_front()
            .unwrap_or(unique_hash.get_txid());
        seen_ats.insert(txid, time);
    }

    // build the tx update with fuzzed data
    let tx_update = TxUpdate {
        txs,
        txouts,
        anchors: todo!(),
        seen_ats: todo!(),
        evicted_ats: todo!(),
    };

    // generate the chain/checkpoints

    let update = Update {
        last_active_indices,
        tx_update: todo!(),
        chain: todo!(),
    };

    match wallet.apply_update(update) {
        Ok(result) => todo!(),
        Err(_) => return,
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
