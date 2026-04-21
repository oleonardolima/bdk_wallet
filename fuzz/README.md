# BDK Wallet Fuzzing

This crate provides structure-aware fuzzing for BDK wallet components using libfuzzer.

## Architecture

The fuzzing infrastructure uses the `Arbitrary` trait for structured input generation instead of raw byte manipulation. This provides:

- **Type Safety**: Compile-time guarantees for input structure
- **Better Coverage**: Smart generation of valid wallet operations
- **Maintainability**: Clear, readable code without macro magic
- **Efficiency**: Focused generation of interesting test cases

## Key Components

- `arbitrary_types.rs`: Defines all fuzzed types with `Arbitrary` implementations
  - Basic types (TxId, BlockHash, Amount, etc.)
  - Wallet operations (ApplyUpdate, CreateTransaction, PersistAndLoad)
  - Transaction building with comprehensive options
  - Complete wallet updates with chain data

## How does it work?

The fuzzer generates structured inputs using the `Arbitrary` trait:

1. `FuzzInput` contains a sequence of `FuzzedWalletOperation`s
2. Each operation is one of: ApplyUpdate, CreateTransaction, or PersistAndLoad
3. Operations contain realistic data with weighted probabilities
4. The fuzzer executes all operations on a fresh wallet instance
5. Errors are handled gracefully to continue fuzzing

## How do I run the fuzz tests locally?

### Running with LibFuzzer

First off, libFuzzer requires nightly version of Rust.

```bash
rustup install nightly
```

Install cargo-fuzz:
```bash
cargo +nightly install cargo-fuzz
```

Run the fuzzer:
```bash
cd fuzz
cargo +nightly fuzz run bdk_wallet_target
```

Run with specific options:
```bash
cargo +nightly fuzz run bdk_wallet_target  --features "libfuzzer_fuzz" -- -max_len=10000 -timeout=10
```

### Running with AFL 

Install the afl toolchain: 

```bash
cargo install cargo-afl
```
Build the project with: 

```bash
cargo afl build --features afl_fuzz
```

AFL strictly requires starting inputs, and will not execute at all without being provided an input directory containing at least one example input.
To generate seeds inputs to be used by AFL: 

```bash
cd write_seed && cargo run -- in 
```

Finally you can run the fuzzer:
```bash
cargo afl fuzz -i write_seed/in -o ../target/out -- ../target/debug/bdk_wallet_target
```
### Running with HongFuzz

To install honggfuzz, simply run:

```bash
cargo update
cargo install --force honggfuzz
```
To run fuzzing using honggfuzz, do:

```bash
export CPU_COUNT=1 # replace as needed
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
export HFUZZ_RUN_ARGS="-n $CPU_COUNT --exit_upon_crash"
export TARGET="bdk_wallet_target" # replace with the target to be fuzzed
cargo hfuzz run bdk_wallet_target --manifest-path Cargo.toml
```
## How do I add a new fuzz test target?

1. Define new arbitrary types in `src/arbitrary_types.rs`
2. Implement the `Arbitrary` trait with appropriate constraints
3. Add conversion methods to BDK types
4. Create a new fuzz target in `src/`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use your_module::YourFuzzInput;

fuzz_target!(|input: YourFuzzInput| {
    // Your fuzzing logic here
});
```

## How do I reproduce a crashing fuzz test?

When the fuzzer finds a crash, it saves the input to `fuzz/artifacts/`. To reproduce:

```bash
cargo +nightly fuzz run bdk_wallet_target fuzz/artifacts/bdk_wallet/crash-<hash>
```

You can also minimize the crash input:
```bash
cargo +nightly fuzz tmin bdk_wallet_target fuzz/artifacts/bdk_wallet/crash-<hash>
```

# How do I generate coverage report?

In order to generate coverage report you need to install the rustup components for the nightly toolchain instead of the default:

```bash
rustup component add --toolchain nightly llvm-tools-preview
```

After that run:
```bash
cargo +nightly fuzz coverage <target_name>
```

The resulting coverage data will be located at fuzz/coverage/<target_name>/coverage.profdata.


## Structure-Aware Fuzzing Benefits

Unlike traditional fuzzing that manipulates raw bytes, our structure-aware approach:

1. Generates valid wallet operations by construction
2. Uses weighted probabilities for realistic test scenarios
3. Maintains invariants automatically
4. Provides better code coverage with fewer iterations
5. Makes debugging easier with structured, readable inputs