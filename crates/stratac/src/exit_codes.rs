//! Deterministic process exit codes for `stratac` CI integration.

/// Command succeeded (`0`).
pub const EXIT_OK: i32 = 0;
/// Compilation, syntax, semantic, or CLI usage error (`1`).
pub const EXIT_COMPILE_ERROR: i32 = 1;
/// One or more headless `sim_test` assertions failed (`2`).
pub const EXIT_SIM_TEST_FAILED: i32 = 2;
/// Static layout assertion, differential parity, or `--fmt --check` assertion failed (`3`).
pub const EXIT_PARITY_OR_ASSERT_FAILED: i32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies all deterministic CI exit codes are distinct non-negative process codes.
    #[test]
    fn exit_codes_are_unique_and_documented() {
        let codes = [
            EXIT_OK,
            EXIT_COMPILE_ERROR,
            EXIT_SIM_TEST_FAILED,
            EXIT_PARITY_OR_ASSERT_FAILED,
        ];
        assert_eq!(codes, [0, 1, 2, 3]);
    }
}
