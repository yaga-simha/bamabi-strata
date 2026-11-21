//! 64-byte `SystemTelemetryDigest64` binary IPC frame codec and `bam/*` BRP JSON-RPC schema
//! store feeding live IDE CodeLens timings and memory allocation telemetry.

use bamabi_sys::{fnv1a_64_init, fnv1a_64_update_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Magic cookie `"STRT"` in little-endian (`0x5354_5254`).
pub const TELEMETRY_DIGEST_MAGIC: u32 = 0x5354_5254;
/// Wire format version for `SystemTelemetryDigest64`.
pub const TELEMETRY_DIGEST_VERSION: u16 = 1;

/// Fixed 64-byte wire frame emitted per scheduled system by `ModTelemetryEndpoint`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTelemetryDigest64 {
    /// Wire magic cookie (`TELEMETRY_DIGEST_MAGIC`).
    pub magic: u32,
    /// Protocol version (`TELEMETRY_DIGEST_VERSION`).
    pub version: u16,
    /// Telemetry status bitflags (`0` = nominal, bit `0` = quarantine active).
    pub flags: u16,
    /// Deterministic 64-bit FNV-1a hash of the canonical system name (`system_name_hash`).
    pub system_name_hash: u64,
    /// Monotonic simulation frame index.
    pub frame_index: u64,
    /// Rolling average execution duration in nanoseconds.
    pub avg_ns: u64,
    /// Rolling 99th-percentile execution duration in nanoseconds.
    pub p99_ns: u64,
    /// Total entities matched on the latest frame.
    pub entity_count: u64,
    /// Dirty rows flushed via `&mut?` selective tick coalescing on the latest frame.
    pub dirty_rows: u64,
    /// Steady-state heap bytes allocated inside this system invocation (`0` target).
    pub alloc_bytes: u64,
}

const _: () = {
    assert!(core::mem::size_of::<SystemTelemetryDigest64>() == 64);
    assert!(core::mem::align_of::<SystemTelemetryDigest64>() == 8);
};

/// Errors decoding 64-byte telemetry frames or `bam/*` BRP JSON-RPC payloads.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Input frame length did not equal 64 bytes.
    #[error("invalid SystemTelemetryDigest64 length {actual} (expected 64)")]
    InvalidLength {
        /// Actual slice length.
        actual: usize,
    },
    /// Magic cookie mismatch.
    #[error("invalid telemetry magic 0x{actual:08X} (expected 0x{TELEMETRY_DIGEST_MAGIC:08X})")]
    InvalidMagic {
        /// Actual magic integer.
        actual: u32,
    },
    /// Malformed `bam/*` BRP JSON payload.
    #[error("invalid BRP schema JSON payload: {0}")]
    InvalidBrpJson(String),
}

impl SystemTelemetryDigest64 {
    /// Serializes this 64-byte digest into canonical little-endian wire bytes safely without unsafe.
    #[must_use]
    pub fn to_le_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.system_name_hash.to_le_bytes());
        buf[16..24].copy_from_slice(&self.frame_index.to_le_bytes());
        buf[24..32].copy_from_slice(&self.avg_ns.to_le_bytes());
        buf[32..40].copy_from_slice(&self.p99_ns.to_le_bytes());
        buf[40..48].copy_from_slice(&self.entity_count.to_le_bytes());
        buf[48..56].copy_from_slice(&self.dirty_rows.to_le_bytes());
        buf[56..64].copy_from_slice(&self.alloc_bytes.to_le_bytes());
        buf
    }

    /// Parses a canonical 64-byte little-endian `SystemTelemetryDigest64` frame.
    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, TelemetryError> {
        if bytes.len() != 64 {
            return Err(TelemetryError::InvalidLength {
                actual: bytes.len(),
            });
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != TELEMETRY_DIGEST_MAGIC {
            return Err(TelemetryError::InvalidMagic { actual: magic });
        }
        let u64_at = |off: usize| -> u64 {
            u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ])
        };
        Ok(Self {
            magic,
            version: u16::from_le_bytes([bytes[4], bytes[5]]),
            flags: u16::from_le_bytes([bytes[6], bytes[7]]),
            system_name_hash: u64_at(8),
            frame_index: u64_at(16),
            avg_ns: u64_at(24),
            p99_ns: u64_at(32),
            entity_count: u64_at(40),
            dirty_rows: u64_at(48),
            alloc_bytes: u64_at(56),
        })
    }
}

/// Computes the deterministic 64-bit FNV-1a system name hash matching `SystemTelemetryDigest64`.
#[must_use]
pub fn system_name_hash(name: &str) -> u64 {
    let mut h = fnv1a_64_init();
    h = fnv1a_64_update_bytes(h, name.as_bytes());
    h
}

/// Live `bam/*` BRP JSON-RPC schema metadata entry received from a running Bevy host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrpSchemaEntry {
    /// Canonical component or system name.
    pub canonical_name: String,
    /// Schema fingerprint reported over BRP (`0x...` or u64).
    pub schema_fingerprint: u64,
    /// Component byte size.
    pub size: usize,
    /// Component alignment.
    pub align: usize,
}

#[derive(Deserialize)]
struct BrpEnvelope {
    method: Option<String>,
    result: Option<serde_json::Value>,
}

/// Parses a `bam/*` BRP JSON-RPC response payload extracting live schema descriptors.
pub fn parse_brp_schema_json(payload: &str) -> Result<Vec<BrpSchemaEntry>, TelemetryError> {
    let env: BrpEnvelope =
        serde_json::from_str(payload).map_err(|e| TelemetryError::InvalidBrpJson(e.to_string()))?;
    if let Some(m) = &env.method
        && !m.starts_with("bam/")
    {
        return Err(TelemetryError::InvalidBrpJson(format!(
            "unexpected BRP method `{m}` (expected `bam/*`)"
        )));
    }
    let Some(res) = env.result else {
        return Ok(Vec::new());
    };
    if res.is_array() {
        let entries: Vec<BrpSchemaEntry> = serde_json::from_value(res)
            .map_err(|e| TelemetryError::InvalidBrpJson(e.to_string()))?;
        return Ok(entries);
    }
    if let Some(list) = res.get("schemas") {
        let entries: Vec<BrpSchemaEntry> = serde_json::from_value(list.clone())
            .map_err(|e| TelemetryError::InvalidBrpJson(e.to_string()))?;
        return Ok(entries);
    }
    Ok(Vec::new())
}

/// Thread-safe store holding the latest live per-system telemetry digests and BRP schemas.
#[derive(Debug, Clone, Default)]
pub struct TelemetryStore {
    inner: Arc<RwLock<TelemetryInner>>,
}

#[derive(Debug, Default)]
struct TelemetryInner {
    by_hash: BTreeMap<u64, SystemTelemetryDigest64>,
    schemas: BTreeMap<String, BrpSchemaEntry>,
}

impl TelemetryStore {
    /// Creates an empty [`TelemetryStore`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests one raw 64-byte `SystemTelemetryDigest64` wire packet.
    pub fn ingest_digest_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<SystemTelemetryDigest64, TelemetryError> {
        let digest = SystemTelemetryDigest64::from_le_bytes(bytes)?;
        if let Ok(mut guard) = self.inner.write() {
            guard.by_hash.insert(digest.system_name_hash, digest);
        }
        Ok(digest)
    }

    /// Records a [`SystemTelemetryDigest64`] directly.
    pub fn record_digest(&self, digest: SystemTelemetryDigest64) {
        if let Ok(mut guard) = self.inner.write() {
            guard.by_hash.insert(digest.system_name_hash, digest);
        }
    }

    /// Looks up the latest digest for a system name.
    #[must_use]
    pub fn get_for_system(&self, name: &str) -> Option<SystemTelemetryDigest64> {
        let hash = system_name_hash(name);
        self.inner
            .read()
            .ok()
            .and_then(|g| g.by_hash.get(&hash).copied())
    }

    /// Ingests a `bam/*` BRP JSON-RPC schema payload.
    pub fn ingest_brp_json(&self, json: &str) -> Result<usize, TelemetryError> {
        let entries = parse_brp_schema_json(json)?;
        let count = entries.len();
        if let Ok(mut guard) = self.inner.write() {
            for e in entries {
                guard.schemas.insert(e.canonical_name.clone(), e);
            }
        }
        Ok(count)
    }

    /// Retrieves live BRP schema metadata for a canonical component name.
    #[must_use]
    pub fn get_schema(&self, canonical_name: &str) -> Option<BrpSchemaEntry> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.schemas.get(canonical_name).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies wire codec rejects truncated packets, bad magic cookies, and unknown BRP methods.
    #[test]
    fn telemetry_codec_and_brp_error_paths() {
        assert!(matches!(
            SystemTelemetryDigest64::from_le_bytes(&[0u8; 63]),
            Err(TelemetryError::InvalidLength { actual: 63 })
        ));
        let bad_magic = [0u8; 64];
        assert!(matches!(
            SystemTelemetryDigest64::from_le_bytes(&bad_magic),
            Err(TelemetryError::InvalidMagic { .. })
        ));
        let err = parse_brp_schema_json(r#"{"method":"other/list","result":[]}"#).unwrap_err();
        assert!(matches!(err, TelemetryError::InvalidBrpJson(_)));
    }

    /// Verifies `TelemetryStore` ingest/lookup round-trips for binary packets and BRP schemas.
    #[test]
    fn telemetry_store_records_digest_and_schema() {
        let store = TelemetryStore::new();
        let digest = SystemTelemetryDigest64 {
            magic: TELEMETRY_DIGEST_MAGIC,
            version: TELEMETRY_DIGEST_VERSION,
            flags: 0,
            system_name_hash: system_name_hash("physics::step"),
            frame_index: 42,
            avg_ns: 1200,
            p99_ns: 3400,
            entity_count: 1024,
            dirty_rows: 12,
            alloc_bytes: 0,
        };
        store
            .ingest_digest_bytes(&digest.to_le_bytes())
            .expect("valid digest packet");
        assert_eq!(store.get_for_system("physics::step"), Some(digest));

        let n = store
            .ingest_brp_json(
                r#"{"method":"bam/schema","result":{"schemas":[{"canonical_name":"demo::Pos","schema_fingerprint":123,"size":8,"align":4}]}}"#,
            )
            .expect("valid BRP schema");
        assert_eq!(n, 1);
        assert_eq!(store.get_schema("demo::Pos").unwrap().size, 8);
    }
}
