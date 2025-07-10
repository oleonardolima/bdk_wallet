#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, VecDeque};

use bdk_wallet::{
    bitcoin::{self, hashes::Hash, BlockHash, Network, Txid},
    chain::{local_chain::CannotConnectError, TxUpdate},
    rusqlite::Connection,
    KeychainKind, Update, Wallet,
};
use bdk_wallet_fuzz::fuzz_utils::*;

// descriptors
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

// network
const NETWORK: Network = Network::Testnet;

fuzz_target!(|data: &[u8]| {
    // creates initial wallet.
    let mut db_conn = Connection::open_in_memory()
        .expect("Should start an in-memory database connection successfully!");
    let wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
        .network(NETWORK)
        .create_wallet(&mut db_conn);

    // asserts that the wallet creation did not fail.
    let mut wallet = match wallet {
        Ok(wallet) => wallet,
        Err(_) => return,
    };

    // fuzzed code goes here.
    // loop {
    //     let mut new_data = data;
    //     let wallet_action = consume_wallet_action(&mut new_data);
    //     match wallet_action {
    //         None => return,
    //         Some(action) => todo!(),
    //     };
    // };
    let mut new_data = data;
    while let Some(action) = consume_wallet_action(&mut new_data) {
        match action {
            WalletAction::ApplyUpdate => {
                let mut new_data = data;
                create_and_apply_update(&mut new_data, &mut wallet).unwrap()
            }
            WalletAction::CreateTx => {
                let new_data = data;

                // generate fuzzed tx builder
                let tx_builder = consume_tx_builder(new_data, &mut wallet);
                let tx_builder = match tx_builder {
                    Some(tx_builder) => tx_builder,
                    None => continue,
                };

                // generate fuzzed psbt
                let mut psbt = match tx_builder.finish() {
                    Ok(psbt) => psbt,
                    Err(_) => continue,
                };

                // generate fuzzed sign options
                let sign_options = consume_sign_options(new_data);

                // generate fuzzed signed psbt
                let _is_signed = match wallet.sign(&mut psbt, sign_options.clone()) {
                    Ok(is_signed) => is_signed,
                    Err(_) => continue,
                };

                // generated fuzzed finalized psbt
                // extract and apply fuzzed tx
                match wallet.finalize_psbt(&mut psbt, sign_options) {
                    Ok(is_finalized) => match is_finalized {
                        true => match psbt.extract_tx() {
                            Ok(tx) => {
                                let mut update = Update::default();
                                update.tx_update.txs.push(tx.into());
                                wallet.apply_update(update).unwrap()
                            }
                            Err(e) => {
                                assert!(matches!(
                                    e,
                                    bitcoin::psbt::ExtractTxError::AbsurdFeeRate { .. }
                                ));
                                return;
                            }
                        },
                        false => continue,
                    },
                    Err(_) => continue,
                }
            }
            WalletAction::PersistAndLoad => {
                let expected_balance = wallet.balance();
                let expected_internal_index = wallet.next_derivation_index(KeychainKind::Internal);
                let expected_external_index = wallet.next_derivation_index(KeychainKind::External);
                let expected_tip = wallet.latest_checkpoint();
                let expected_genesis_hash =
                    BlockHash::from_byte_array(NETWORK.chain_hash().to_bytes());

                // generate fuzzed persist
                wallet
                    .persist(&mut db_conn)
                    .expect("It should always persist successfully!");

                // generate fuzzed load
                wallet = Wallet::load()
                    .descriptor(KeychainKind::External, Some(EXTERNAL_DESCRIPTOR))
                    .descriptor(KeychainKind::Internal, Some(INTERNAL_DESCRIPTOR))
                    .check_network(NETWORK)
                    .check_genesis_hash(expected_genesis_hash)
                    .load_wallet(&mut db_conn)
                    .expect("It should always load from persistence successfully!")
                    .expect("It should load the wallet successfully!");

                // verify the persisted data is accurate
                assert_eq!(wallet.network(), NETWORK);
                assert_eq!(wallet.balance(), expected_balance);
                assert_eq!(
                    wallet.next_derivation_index(KeychainKind::Internal),
                    expected_internal_index
                );
                assert_eq!(
                    wallet.next_derivation_index(KeychainKind::External),
                    expected_external_index
                );
                assert_eq!(wallet.latest_checkpoint(), expected_tip);
            }
        }
    }
});

fn create_and_apply_update(
    data: &mut &[u8],
    wallet: &mut Wallet,
) -> Result<(), CannotConnectError> {
    let new_data = data;

    // generated fuzzed keychain indices.
    let internal_indices = consume_keychain_indices(new_data, KeychainKind::Internal);
    let external_indices = consume_keychain_indices(new_data, KeychainKind::External);

    let mut last_active_indices: BTreeMap<KeychainKind, u32> = BTreeMap::new();
    last_active_indices.extend(internal_indices);
    last_active_indices.extend(external_indices);

    // generate fuzzed tx update.
    let txs = consume_txs(new_data, wallet);

    let unconfirmed_txids: VecDeque<Txid> = txs.iter().map(|tx| tx.compute_txid()).collect();

    let txouts = consume_txouts(new_data);
    let anchors = consume_anchors(new_data, unconfirmed_txids.clone());
    let seen_ats = consume_seen_ats(new_data, unconfirmed_txids.clone());
    let evicted_ats = consume_evicted_ats(new_data, unconfirmed_txids.clone());

    // build the tx update with fuzzed data
    let mut tx_update = TxUpdate::default();
    tx_update.txs = txs;
    tx_update.txouts = txouts;
    tx_update.anchors = anchors;
    tx_update.seen_ats = seen_ats;
    tx_update.evicted_ats = evicted_ats;

    // generate fuzzed chain.
    let chain = consume_checkpoint(new_data, wallet);

    // apply fuzzed update.
    let update = Update {
        last_active_indices,
        tx_update,
        chain: Some(chain),
    };

    wallet.apply_update(update)
}

fn create_and_apply_tx() {
    todo!()
}
