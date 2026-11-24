#![forbid(unsafe_code)]

//! Property-based tests for `strata_lsp` Layer-0 `SystemTelemetryDigest64` (`"BAMT"`) wire codec.

use proptest::prelude::*;
use strata_lsp::{
    SYSTEM_TELEMETRY_DIGEST_SIZE, SYSTEM_TELEMETRY_DIGEST_VERSION, SYSTEM_TELEMETRY_MAGIC,
    SystemTelemetryDigest64, TelemetryError, decode_digest_slice,
};

proptest! {
    #[test]
    fn system_telemetry_digest64_wire_roundtrip_is_lossless(
        flags in any::<u16>(),
        mod_id in any::<u64>(),
        system_hash in any::<u64>(),
        frame_seq in any::<u64>(),
        matched_entities in any::<u32>(),
        matched_tables in any::<u32>(),
        skipped_summary_tick_tables in any::<u32>(),
        chunks in any::<u32>(),
        p50_us in any::<u32>(),
        p99_us in any::<u32>(),
        commands_queued in any::<u32>(),
        reserved in any::<u32>(),
    ) {
        let msg = SystemTelemetryDigest64 {
            magic: SYSTEM_TELEMETRY_MAGIC,
            version: SYSTEM_TELEMETRY_DIGEST_VERSION,
            flags,
            mod_id,
            system_hash,
            frame_seq,
            matched_entities,
            matched_tables,
            skipped_summary_tick_tables,
            chunks,
            p50_us,
            p99_us,
            commands_queued,
            reserved,
        };
        let bytes = msg.to_le_bytes();
        prop_assert_eq!(bytes.len(), SYSTEM_TELEMETRY_DIGEST_SIZE);
        prop_assert_eq!(decode_digest_slice(&bytes).unwrap(), msg);
    }

    #[test]
    fn system_telemetry_digest64_rejects_arbitrary_non_canonical_packets(
        raw in proptest::collection::vec(any::<u8>(), 0..=128)
    ) {
        if raw.len() != SYSTEM_TELEMETRY_DIGEST_SIZE {
            let is_invalid_len = matches!(
                decode_digest_slice(&raw),
                Err(TelemetryError::InvalidLength { .. })
            );
            prop_assert!(is_invalid_len);
        } else {
            let magic: [u8; 4] = raw[0..4].try_into().unwrap();
            let version = u16::from_le_bytes(raw[4..6].try_into().unwrap());
            if magic != SYSTEM_TELEMETRY_MAGIC {
                let is_invalid_magic = matches!(
                    decode_digest_slice(&raw),
                    Err(TelemetryError::InvalidMagic { .. })
                );
                prop_assert!(is_invalid_magic);
            } else if version != SYSTEM_TELEMETRY_DIGEST_VERSION {
                let is_unsupported_ver = matches!(
                    decode_digest_slice(&raw),
                    Err(TelemetryError::UnsupportedVersion { .. })
                );
                prop_assert!(is_unsupported_ver);
            } else {
                prop_assert!(decode_digest_slice(&raw).is_ok());
            }
        }
    }
}
