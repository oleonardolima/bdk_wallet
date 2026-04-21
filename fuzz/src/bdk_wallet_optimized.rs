use bdk_wallet::{rusqlite::Connection, PersistedWallet, SignOptions, Wallet};

use crate::types::{
    arbitrary_types::{EXTERNAL_DESCRIPTOR, NETWORK},
    arbitrary_types_optimized::{OptimizedFuzzInput, OptimizedWalletOperation},
};

#[inline]
fn do_test(
    operations: OptimizedFuzzInput,
    wallet: &mut PersistedWallet<Connection>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for operation in operations.operations {
        match operation {
            OptimizedWalletOperation::ApplyUpdate(update) => {
                let update = update.into_update(wallet);
                wallet.apply_update(update)?;
            }
            OptimizedWalletOperation::CreateTransaction {
                builder,
                should_sign,
            } => {
                let mut psbt = match builder.build_with_wallet(wallet) {
                    Ok(psbt) => psbt,
                    Err(_) => continue,
                };

                if should_sign {
                    // Use default sign options for performance
                    let _ = wallet.sign(&mut psbt, SignOptions::default());
                }
            }
        }
    }
    Ok(())
}

pub fn bdk_wallet_optimized_fuzz_test(
    ops: OptimizedFuzzInput,
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

    do_test(ops, &mut wallet)
}
