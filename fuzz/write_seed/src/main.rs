/// Seed generator for AFL++ fuzzing of bdk_wallet

use std::fs;
use std::path::Path;

fn main() -> std::io::Result<()> {
	let mut iter = std::env::args();
	iter.next().unwrap(); // program name
	let path = iter.next().expect("Requires a path as the first argument");
    let out_dir = Path::new(&path);

    // Seed 1: Empty input (Vec with 0 length)
    // Format: little-endian u32 for length (0)
    write_seed_raw(out_dir, "001_empty", &[0, 0, 0, 0])?;

    // Seed 2: Single operation - PersistAndLoad (enum variant 2)
    // Vec length: 1, then variant: 2
    let mut seed2 = vec![1u8, 0, 0, 0];  // Vec length = 1
    seed2.push(2);  // PersistAndLoad operation
    write_seed_raw(out_dir, "002_persist_load", &seed2)?;

    // Seed 3: ApplyUpdate operation (variant 0)
    // Provides seed data for building an update
    let seed3 = generate_pattern_bytes(200, PatternType::Sequential);
    write_seed_raw(out_dir, "003_apply_update", &seed3)?;

    // Seed 4: CreateTransaction operation (variant 1)
    let seed4 = generate_pattern_bytes(300, PatternType::Random);
    write_seed_raw(out_dir, "004_create_tx", &seed4)?;

    // Seed 5: Multiple operations alternating patterns
    let seed5 = generate_pattern_bytes(400, PatternType::Alternating);
    write_seed_raw(out_dir, "005_multi_ops_alt", &seed5)?;

    // Seed 6: All zeros (edge case)
    let seed6 = vec![0u8; 256];
    write_seed_raw(out_dir, "006_all_zeros", &seed6)?;

    // Seed 7: All ones (edge case)
    let seed7 = vec![0xFFu8; 256];
    write_seed_raw(out_dir, "007_all_ones", &seed7)?;

    // Seed 8: XOR pattern
    let seed8 = generate_pattern_bytes(256, PatternType::XOR);
    write_seed_raw(out_dir, "008_xor_pattern", &seed8)?;

    // Seed 9: Gradual intensity increase
    let seed9 = generate_pattern_bytes(512, PatternType::Gradual);
    write_seed_raw(out_dir, "009_gradual", &seed9)?;

    // Seed 10: High entropy data
    let seed10 = generate_pattern_bytes(1024, PatternType::Entropy);
    write_seed_raw(out_dir, "010_high_entropy", &seed10)?;

    println!("✓ Seed generation complete");
    println!("\nGenerated seeds for AFL++:");
    println!("  Location: {}", out_dir.display());
    
    let mut total_size = 0;
    for entry in fs::read_dir(out_dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        let size = metadata.len();
        total_size += size;
        println!("  {} ({} bytes)", path.file_name().unwrap().to_string_lossy(), size);
    }
    
    println!("\nTotal seed data: {} bytes", total_size);
    println!("\nTo start fuzzing, run:");
    println!("  cd .. && cargo afl fuzz -i write_seed/in -o ../target/out -- ../target/debug/bdk_wallet_target");

    Ok(())
}

#[derive(Copy, Clone)]
enum PatternType {
    Sequential,
    Random,
    Alternating,
    XOR,
    Gradual,
    Entropy,
}

/// Generate seed bytes with different patterns
fn generate_pattern_bytes(size: usize, pattern: PatternType) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    let mut rng_state = 1234567u64;

    for i in 0..size {
        bytes[i] = match pattern {
            PatternType::Sequential => (i % 256) as u8,
            
            PatternType::Random => {
                // Simple LCG PRNG
                rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                (rng_state >> 16) as u8
            }
            
            PatternType::Alternating => if i % 2 == 0 { 0xAA } else { 0x55 },
            
            PatternType::XOR => (i as u8) ^ (i.wrapping_shr(4) as u8),
            
            PatternType::Gradual => {
                let intensity = (i * 255) / size;
                intensity as u8
            }
            
            PatternType::Entropy => {
                // Mix multiple patterns
                let a = (i as u8).wrapping_mul(17);
                let b = ((i >> 3) as u8).wrapping_mul(31);
                let c = ((i >> 5) as u8).wrapping_mul(67);
                a.wrapping_add(b).wrapping_add(c)
            }
        };
    }

    bytes
}

/// Write raw seed bytes directly
fn write_seed_raw(out_dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    let path = out_dir.join(name);
    fs::write(&path, data)?;
    Ok(())
}
