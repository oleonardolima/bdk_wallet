#![cfg_attr(feature = "libfuzzer_fuzz", no_main)]

extern crate bdk_wallet_fuzz;

#[allow(unused)]
use bdk_wallet_fuzz::{
    bdk_wallet_optimized::bdk_wallet_optimized_fuzz_test,
    types::arbitrary_types_optimized::OptimizedFuzzInput,
};

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;
#[cfg(feature = "afl_fuzz")]
fn main() {
    fuzz!(|data: OptimizedFuzzInput| {
        bdk_wallet_optimized_fuzz_test(data).unwrap();
    });
}

#[cfg(feature = "honggfuzz_fuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz_fuzz")]
fn main() {
	loop {
		fuzz!(|data: OptimizedFuzzInput| {
			bdk_wallet_optimized_fuzz_test(data).unwrap();
		});
	}
}

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use] extern crate libfuzzer_sys;
#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: OptimizedFuzzInput| {
    bdk_wallet_optimized_fuzz_test(data).unwrap();
});
