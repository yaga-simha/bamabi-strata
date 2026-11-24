//! Kani Bounded Model Checking Proof Obligations for `strata_lsp`.
//!
//! Specifically proves **PO-S8**: canonical lossless wire round-trip and strict header/length
//! rejection of the 64-byte [`bamabi_sys::SystemTelemetryDigest64`] (`*b"BAMT"`) IPC digest
//! envelope ingested from live Bevy / `bamabi` hosts.

#[cfg(any(kani, test))]
use crate::telemetry::{
    SYSTEM_TELEMETRY_DIGEST_SIZE, SYSTEM_TELEMETRY_DIGEST_VERSION, SYSTEM_TELEMETRY_MAGIC,
    SystemTelemetryDigest64, TelemetryError, decode_digest_slice,
};

/// PO-S8: `SystemTelemetryDigest64::to_le_bytes` -> `from_le_slice` is an exact lossless bijection
/// whenever `magic == SYSTEM_TELEMETRY_MAGIC` (`b"BAMT"`) and `version == 1`, and strictly rejects
/// any packet with invalid magic, unsupported version, or truncated byte slice (`len < 64`).
#[cfg_attr(kani, kani::proof)]
#[cfg_attr(not(kani), test)]
pub fn po_s8_system_telemetry_digest64_wire_roundtrip_and_rejection() {
    let original = SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: kani_any_u16(),
        mod_id: kani_any_u64(),
        system_hash: kani_any_u64(),
        frame_seq: kani_any_u64(),
        matched_entities: kani_any_u32(),
        matched_tables: kani_any_u32(),
        skipped_summary_tick_tables: kani_any_u32(),
        chunks: kani_any_u32(),
        p50_us: kani_any_u32(),
        p99_us: kani_any_u32(),
        commands_queued: kani_any_u32(),
        reserved: kani_any_u32(),
    };

    let wire: [u8; SYSTEM_TELEMETRY_DIGEST_SIZE] = original.to_le_bytes();
    let decoded = decode_digest_slice(&wire).expect("valid BAMT v1 digest must decode");
    assert_eq!(decoded, original);

    let bad_magic: [u8; 4] = [kani_any_u8(), kani_any_u8(), kani_any_u8(), kani_any_u8()];
    #[cfg(kani)]
    kani::assume(bad_magic != SYSTEM_TELEMETRY_MAGIC);
    #[cfg(not(kani))]
    let bad_magic = if bad_magic == SYSTEM_TELEMETRY_MAGIC {
        *b"NOPE"
    } else {
        bad_magic
    };

    let mut corrupted = wire;
    corrupted[0..4].copy_from_slice(&bad_magic);
    assert!(matches!(
        decode_digest_slice(&corrupted),
        Err(TelemetryError::InvalidMagic { actual }) if actual == bad_magic
    ));

    let bad_ver: u16 = kani_any_u16();
    #[cfg(kani)]
    kani::assume(bad_ver != SYSTEM_TELEMETRY_DIGEST_VERSION);
    #[cfg(not(kani))]
    let bad_ver = if bad_ver == SYSTEM_TELEMETRY_DIGEST_VERSION {
        99
    } else {
        bad_ver
    };
    let mut bad_ver_wire = wire;
    bad_ver_wire[4..6].copy_from_slice(&bad_ver.to_le_bytes());
    assert!(matches!(
        decode_digest_slice(&bad_ver_wire),
        Err(TelemetryError::UnsupportedVersion { actual }) if actual == bad_ver
    ));

    let len: usize = kani_any_usize_lt_64();
    assert!(matches!(
        decode_digest_slice(&wire[..len]),
        Err(TelemetryError::InvalidLength { actual }) if actual == len
    ));
}

#[cfg(kani)]
fn kani_any_u8() -> u8 {
    kani::any()
}

#[cfg(all(not(kani), test))]
fn kani_any_u8() -> u8 {
    0xAA
}

#[cfg(kani)]
fn kani_any_u16() -> u16 {
    kani::any()
}

#[cfg(all(not(kani), test))]
fn kani_any_u16() -> u16 {
    0x0003
}

#[cfg(kani)]
fn kani_any_u32() -> u32 {
    kani::any()
}

#[cfg(all(not(kani), test))]
fn kani_any_u32() -> u32 {
    0x1234_5678
}

#[cfg(kani)]
fn kani_any_u64() -> u64 {
    kani::any()
}

#[cfg(all(not(kani), test))]
fn kani_any_u64() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

#[cfg(kani)]
fn kani_any_usize_lt_64() -> usize {
    let v: usize = kani::any();
    kani::assume(v < 64);
    v
}

#[cfg(all(not(kani), test))]
fn kani_any_usize_lt_64() -> usize {
    63
}
