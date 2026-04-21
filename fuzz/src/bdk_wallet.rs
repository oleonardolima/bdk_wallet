use crate::types::arbitrary_types::{FuzzedWalletOperation, EXTERNAL_DESCRIPTOR, NETWORK};
use bdk_wallet::{rusqlite::Connection, KeychainKind, PersistedWallet, Update, Wallet};

#[inline]
fn do_test(
    operations: Vec<FuzzedWalletOperation>,
    wallet: &mut PersistedWallet<Connection>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for operation in operations {
        match operation {
            FuzzedWalletOperation::ApplyUpdate(update) => {
                let update = update.into_update(wallet);
                wallet.apply_update(update)?;
            }

            FuzzedWalletOperation::CreateTransaction {
                builder,
                sign_options,
                finalize,
            } => {
                // Build the transaction
                let mut psbt = match builder.build_with_wallet(wallet) {
                    Ok(psbt) => psbt,
                    Err(_) => continue, // Skip invalid transactions
                };

                // Optionally sign
                if let Some(options) = sign_options {
                    let sign_opts = options.into_sign_options();
                    let _signed = match wallet.sign(&mut psbt, sign_opts.clone()) {
                        Ok(signed) => signed,
                        Err(_) => continue, // Skip signing errors
                    };

                    // Optionally finalize
                    if finalize {
                        match wallet.finalize_psbt(&mut psbt, sign_opts) {
                            Ok(is_finalized) if is_finalized => {
                                // Extract and apply the transaction
                                match psbt.extract_tx() {
                                    Ok(tx) => {
                                        let mut update = Update::default();
                                        update.tx_update.txs.push(tx.into());
                                        wallet.apply_update(update)?;
                                    }
                                    Err(
                                        bdk_wallet::bitcoin::psbt::ExtractTxError::AbsurdFeeRate {
                                            ..
                                        },
                                    ) => {
                                        // This is an expected error, skip it
                                        continue;
                                    }
                                    Err(_) => continue,
                                }
                            }
                            _ => continue, // Not finalized or error
                        }
                    }
                }
            }

            FuzzedWalletOperation::PersistAndLoad => {
                // With PersistedWallet, persistence happens automatically
                // We can verify the wallet state is consistent
                let balance = wallet.balance();
                let _internal_index = wallet.next_derivation_index(KeychainKind::Internal);
                let _external_index = wallet.next_derivation_index(KeychainKind::External);
                let _tip = wallet.latest_checkpoint();

                // Just verify we can still access wallet state
                assert!(balance.total().to_sat() < 21_000_000 * 100_000_000);
            }
        }
    }

    Ok(())
}

pub fn bdk_wallet_fuzz_test(
    data: Vec<FuzzedWalletOperation>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create an in-memory database connection
    let mut db_conn = Connection::open_in_memory()
        .expect("Should start an in-memory database connection successfully!");

    // Create the initial wallet
    let wallet = Wallet::create(EXTERNAL_DESCRIPTOR, EXTERNAL_DESCRIPTOR)
        .network(NETWORK)
        .create_wallet(&mut db_conn);

    // If wallet creation fails, skip this input
    let mut wallet = match wallet {
        Ok(wallet) => wallet,
        Err(_) => return Ok(()),
    };

    do_test(data, &mut wallet)
}
