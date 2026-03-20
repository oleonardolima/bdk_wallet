/// Test to demonstrate the RelLockTime issue in dsl.rs
///
/// The issue: older() macro uses .expect() on RelLockTime::from_consensus(),
/// which can panic if given an invalid value.
///
/// This file shows the problem and how to catch it.
use bdk_wallet::descriptor;

#[test]
fn test_older_with_invalid_rellocktime_too_large() {
    // Value with high bit set causes RelLockTime::from_consensus() to fail
    let invalid_value = 0x80000000; // 2147483648

    // This should now return an error instead of panicking
    let result = descriptor!(wsh(older(invalid_value)));
    assert!(
        result.is_err(),
        "Invalid RelLockTime {} should return an error",
        invalid_value
    );

    // Check that it's the right kind of error
    if let Err(descriptor::DescriptorError::Miniscript(miniscript::Error::RelativeLockTime(_))) =
        result
    {
    } else {
        panic!("Expected RelLockTime error, got {:?}", result);
    }
}

#[test]
fn test_older_with_valid_rellocktime_max() {
    // Max valid value is 65,535 (0xFFFF)
    let max_valid_value = 65_535;
    let result = descriptor!(wsh(older(max_valid_value)));
    assert!(result.is_ok(), "Max valid RelLockTime should work");
}

#[test]
fn test_older_with_valid_rellocktime_min() {
    // Min valid value is 1 (0 is not valid for RelLockTime)
    let min_value = 1;

    let result = descriptor!(wsh(older(min_value)));
    assert!(result.is_ok(), "Min valid RelLockTime should work");
}

#[test]
fn test_older_with_valid_common_values() {
    // Common usage: blocks or seconds
    let test_cases = vec![
        1,         // 1 block/second
        144,       // ~1 day in blocks
        1000,      // Common value
        65535,     // Max 16-bit value (common for CSV)
        4_209_713, // Valid but large
    ];

    for value in test_cases {
        let result = descriptor!(wsh(older(value)));
        assert!(result.is_ok(), "Valid RelLockTime {} should work", value);
    }
}

// Alternative: Show how proper error handling should look
#[test]
fn test_demonstrate_proper_error_handling() {
    // This is what the fix should look like - proper Result handling
    // instead of .expect() which panics

    use miniscript::RelLockTime;

    // Valid case
    let valid_lock = RelLockTime::from_consensus(144);
    assert!(
        valid_lock.is_ok(),
        "144 blocks should be a valid RelLockTime"
    );

    // Invalid case
    let invalid_value = 0x8000_0000;
    let invalid_result = RelLockTime::from_consensus(invalid_value);
    assert!(
        invalid_result.is_err(),
        "Value 0x{:x} should return a RelLockTime error",
        invalid_value
    );
}

#[test]
fn test_rel_lock_time_error() {
    // 1. Create the underlying RelLockTime error (high bit set)
    let invalid_value = 0x80000000u32;
    let rel_lock_time_result = miniscript::RelLockTime::from_consensus(invalid_value);
    assert!(rel_lock_time_result.is_err());

    let rel_lock_time_error = rel_lock_time_result.unwrap_err();

    // 2. Wrap it in the Miniscript error variant (matching your new macro logic)
    let minisc_err = miniscript::Error::RelativeLockTime(rel_lock_time_error);

    // 3. Test the From impl (Miniscript -> DescriptorError)
    let error: descriptor::DescriptorError = minisc_err.into();

    // Check that it matches the nested structure
    assert!(matches!(
        error,
        descriptor::DescriptorError::Miniscript(miniscript::Error::RelativeLockTime(_))
    ));

    // 4. Test the Display impl
    let display_string = format!("{}", error);

    assert!(
        display_string.contains("relative locktime"),
        "Display string was: '{}'",
        display_string
    );
}
