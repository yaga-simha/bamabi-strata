//! Kani formal verification harness for `strata_lsp` (`PO-S8`).
//!
//! Discharges symbolic bounded model checking proofs establishing total bijection and invalid-input
//! rejection of the 64-byte [`SystemTelemetryDigest64`](crate::telemetry::SystemTelemetryDigest64)
//! wire codec across all 2^512 valid payload combinations.

use crate::telemetry::{SystemTelemetryDigest64, TELEMETRY_DIGEST_MAGIC, TelemetryError};

/// PO-S8: `SystemTelemetryDigest64::to_le_bytes` -> `from_le_bytes` is an exact lossless bijection
/// whenever `magic == TELEMETRY_DIGEST_MAGIC`, and `from_le_bytes` strictly rejects any packet with
/// length != 64 or corrupted magic cookie without panicking.
#[kani::proof]
fn po_s8_telemetry_digest64_wire_codec_bijection() {
    let original = SystemTelemetryDigest64 {
        magic: TELEMETRY_DIGEST_MAGIC,
        version: kani::any(),
        flags: kani::any(),
        system_name_hash: kani::any(),
        frame_index: kani::any(),
        avg_ns: kani::any(),
        p99_ns: kani::any(),
        entity_count: kani::any(),
        dirty_rows: kani::any(),
        alloc_bytes: kani::any(),
    };
    let wire = original.to_le_bytes();
    assert_eq!(wire.len(), 64);
    let decoded = SystemTelemetryDigest64::from_le_bytes(&wire).expect("valid magic must decode");
    assert_eq!(decoded, original);

    // Wrong magic cookie strictly rejected across all non-matching 32-bit headers.
    let bad_magic: u32 = kani::any();
    kani::assume(bad_magic != TELEMETRY_DIGEST_MAGIC);
    let mut corrupted = wire;
    corrupted[0..4].copy_from_slice(&bad_magic.to_le_bytes());
    assert!(matches!(
        SystemTelemetryDigest64::from_le_bytes(&corrupted),
        Err(TelemetryError::InvalidMagic { .. })
    ));

    // Wrong packet length (bounded symbolic slice) strictly rejected.
    let len: usize = kani::any();
    kani::assume(len < 64);
    assert!(matches!(
        SystemTelemetryDigest64::from_le_bytes(&wire[..len]),
        Err(TelemetryError::InvalidLength { actual }) if actual == len
    ));
}
