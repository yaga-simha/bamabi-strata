#![forbid(unsafe_code)]
//! Property-based (`proptest`) suites for [`strata_lsp`] 64-byte binary telemetry packets.

use proptest::prelude::*;
use strata_lsp::{SystemTelemetryDigest64, TELEMETRY_DIGEST_MAGIC, TelemetryError};

proptest! {
    /// Verifies full 64-byte binary wire round-trip over random field payloads.
    #[test]
    fn telemetry_digest64_roundtrip(
        version in any::<u16>(),
        flags in any::<u16>(),
        system_name_hash in any::<u64>(),
        frame_index in any::<u64>(),
        avg_ns in any::<u64>(),
        p99_ns in any::<u64>(),
        entity_count in any::<u64>(),
        dirty_rows in any::<u64>(),
        alloc_bytes in any::<u64>(),
    ) {
        let msg = SystemTelemetryDigest64 {
            magic: TELEMETRY_DIGEST_MAGIC,
            version,
            flags,
            system_name_hash,
            frame_index,
            avg_ns,
            p99_ns,
            entity_count,
            dirty_rows,
            alloc_bytes,
        };
        let bytes = msg.to_le_bytes();
        prop_assert_eq!(SystemTelemetryDigest64::from_le_bytes(&bytes).unwrap(), msg);
    }

    /// Verifies arbitrary byte slices with wrong length or wrong magic return structured errors.
    #[test]
    fn telemetry_digest64_rejects_arbitrary_corrupt_frames(raw in prop::collection::vec(any::<u8>(), 0..96)) {
        if raw.len() != 64 {
            let is_len_err = matches!(
                SystemTelemetryDigest64::from_le_bytes(&raw),
                Err(TelemetryError::InvalidLength { .. })
            );
            prop_assert!(is_len_err);
        } else {
            let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if magic != TELEMETRY_DIGEST_MAGIC {
                let is_magic_err = matches!(
                    SystemTelemetryDigest64::from_le_bytes(&raw),
                    Err(TelemetryError::InvalidMagic { .. })
                );
                prop_assert!(is_magic_err);
            } else {
                prop_assert!(SystemTelemetryDigest64::from_le_bytes(&raw).is_ok());
            }
        }
    }
}
