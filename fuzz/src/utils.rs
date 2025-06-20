use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    sync::Arc,
};

use bdk_wallet::{
    bitcoin::{self, hashes::Hash, OutPoint, Transaction, TxOut, Txid},
    chain::{BlockId, CheckPoint, ConfirmationBlockTime},
    KeychainKind, Wallet,
};

macro_rules! next_or_return {
    ($iter:expr) => {
        match $iter.next() {
            Some(val) => val,
            None => return Default::default(),
        }
    };
}

pub fn scale(byte: u8) -> u32 {
    (byte as u32) * 0x01000000
}

pub fn scale_u64(byte: u8) -> u64 {
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

pub fn get_last_active_indices(data: &[u8], keychain: KeychainKind) -> BTreeMap<KeychainKind, u32> {
    let mut data_iter = data.iter();
    let mut last_active_indices = BTreeMap::new();
    if *next_or_return!(data_iter) & 0x01 == 0x01 {
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
pub fn get_txs(data: &[u8], wallet: &mut Wallet) -> Vec<Arc<Transaction>> {
    let mut data_iter = data.iter();
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

pub fn get_txouts(data: &[u8]) -> BTreeMap<OutPoint, TxOut> {
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

pub fn get_anchors(
    data: &[u8],
    mut unconfirmed_txids: VecDeque<Txid>,
) -> BTreeSet<(ConfirmationBlockTime, Txid)> {
    let mut data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

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
        let txid = unconfirmed_txids
            .pop_front()
            .unwrap_or(unique_hash.get_txid());
        anchors.insert((anchor, txid));

        // if let Some(txid) = unconfirmed_txids.pop_front() {
        //     anchors.insert((anchor, txid));
        // };
    }
    anchors
}

pub fn get_seen_ats(data: &[u8], mut unconfirmed_txids: VecDeque<Txid>) -> HashSet<(Txid, u64)> {
    let mut data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

    let mut seen_ats = HashSet::new();
    while next_or_return!(data_iter) & 0x01 == 0x01 {
        let time = cmp::min(scale_u64(*next_or_return!(data_iter)), i64::MAX as u64 - 1);
        let txid = unconfirmed_txids
            .pop_front()
            .unwrap_or(unique_hash.get_txid());
        seen_ats.insert((txid, time));
    }
    seen_ats
}

pub fn get_evicted_ats(data: &[u8], mut unconfirmed_txids: VecDeque<Txid>) -> HashSet<(Txid, u64)> {
    let mut data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

    let mut seen_ats = HashSet::new();
    while next_or_return!(data_iter) & 0x01 == 0x01 {
        let time = cmp::min(scale_u64(*next_or_return!(data_iter)), i64::MAX as u64 - 1);
        let txid = unconfirmed_txids
            .pop_front()
            .unwrap_or(unique_hash.get_txid());
        seen_ats.insert((txid, time));
    }
    seen_ats
}

pub fn get_checkpoint(data: &[u8]) -> Option<CheckPoint> {
    let mut data_iter = data.iter();
    let mut unique_hash = UniqueHash::new();

    let mut block_ids = vec![];
    while next_or_return!(data_iter) & 0x01 == 0x01 {
        let height = scale(*next_or_return!(data_iter));
        let hash = unique_hash.get_block_hash();
        let block_id = BlockId { height, hash };

        block_ids.push(block_id);
    }
    CheckPoint::from_block_ids(block_ids).ok()
}
