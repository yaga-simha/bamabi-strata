//! 64-byte [`bamabi_sys::SystemTelemetryDigest64`] (`"BAMT"`) binary IPC frame codec,
//! `bam/*` BRP JSON-RPC schema ingestion, non-blocking socket telemetry subscriber, and thread-safe
//! [`TelemetryStore`].

pub use bamabi_sys::{
    BRP_METHOD_BAM_COMPONENT_SCHEMAS, BRP_METHOD_BAM_HOT_RELOAD, BRP_METHOD_BAM_LIST_MODS,
    BRP_METHOD_BAM_SYSTEM_METRICS, SYSTEM_TELEMETRY_DIGEST_SIZE, SYSTEM_TELEMETRY_DIGEST_VERSION,
    SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64, TELEMETRY_FLAG_BUDGET_BREACHED,
    TELEMETRY_FLAG_FAULTED, TELEMETRY_FLAG_QUARANTINED, TELEMETRY_FLAG_SUMMARY_TICK_ACTIVE,
    TelemetryFrameError, TelemetrySliceError, fnv1a_64_hash_system, fnv1a_64_str,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Canonical 4-byte wire magic prefix (`*b"BAMT"`) matching [`bamabi_sys::SYSTEM_TELEMETRY_MAGIC`].
pub const TELEMETRY_DIGEST_MAGIC: [u8; 4] = SYSTEM_TELEMETRY_MAGIC;

/// Canonical digest wire version (`1`) matching [`bamabi_sys::SYSTEM_TELEMETRY_DIGEST_VERSION`].
pub const TELEMETRY_DIGEST_VERSION: u16 = SYSTEM_TELEMETRY_DIGEST_VERSION;

/// JSON-serializable mirror of [`SystemTelemetryDigest64`] for JSON-RPC transport and tooling tests
/// (`bamabi_sys` itself is `#![no_std]` and intentionally carries no `serde` dependency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTelemetryDigestJson {
    /// Leading 4-byte wire magic (`*b"BAMT"`).
    #[serde(default = "default_magic")]
    pub magic: [u8; 4],
    /// Wire schema version (`1`).
    #[serde(default = "default_version")]
    pub version: u16,
    /// Status bitflags (`TELEMETRY_FLAG_*`).
    #[serde(default)]
    pub flags: u16,
    /// Owning `ModId.0` (`0` for unscoped / host-owned systems).
    #[serde(default)]
    pub mod_id: u64,
    /// Deterministic 64-bit FNV-1a hash of `"{mod_name}::{system_name}"`.
    pub system_hash: u64,
    /// Monotonic frame sequence counter.
    #[serde(default)]
    pub frame_seq: u64,
    /// Number of entities matched/visited on the latest sample.
    #[serde(default)]
    pub matched_entities: u32,
    /// Number of ECS tables matched by the system query.
    #[serde(default)]
    pub matched_tables: u32,
    /// Number of matched tables skipped via Bevy `0.20` `summary_tick` acceleration.
    #[serde(default)]
    pub skipped_summary_tick_tables: u32,
    /// Number of contiguous chunk iterations executed.
    #[serde(default)]
    pub chunks: u32,
    /// Rolling median (`p50`) wall-clock duration in microseconds.
    #[serde(default)]
    pub p50_us: u32,
    /// Rolling 99th-percentile (`p99`) wall-clock duration in microseconds.
    #[serde(default)]
    pub p99_us: u32,
    /// Number of deferred host commands queued on the latest sample.
    #[serde(default)]
    pub commands_queued: u32,
    /// Reserved alignment padding word (`0`).
    #[serde(default)]
    pub reserved: u32,
}

const fn default_magic() -> [u8; 4] {
    SYSTEM_TELEMETRY_MAGIC
}

const fn default_version() -> u16 {
    SYSTEM_TELEMETRY_DIGEST_VERSION
}

impl From<&SystemTelemetryDigest64> for SystemTelemetryDigestJson {
    fn from(d: &SystemTelemetryDigest64) -> Self {
        Self {
            magic: d.magic,
            version: d.version,
            flags: d.flags,
            mod_id: d.mod_id,
            system_hash: d.system_hash,
            frame_seq: d.frame_seq,
            matched_entities: d.matched_entities,
            matched_tables: d.matched_tables,
            skipped_summary_tick_tables: d.skipped_summary_tick_tables,
            chunks: d.chunks,
            p50_us: d.p50_us,
            p99_us: d.p99_us,
            commands_queued: d.commands_queued,
            reserved: d.reserved,
        }
    }
}

impl From<SystemTelemetryDigest64> for SystemTelemetryDigestJson {
    fn from(d: SystemTelemetryDigest64) -> Self {
        Self::from(&d)
    }
}

impl TryFrom<SystemTelemetryDigestJson> for SystemTelemetryDigest64 {
    type Error = TelemetryError;

    fn try_from(json: SystemTelemetryDigestJson) -> Result<Self, Self::Error> {
        if json.magic != SYSTEM_TELEMETRY_MAGIC {
            return Err(TelemetryError::InvalidMagic { actual: json.magic });
        }
        if json.version != SYSTEM_TELEMETRY_DIGEST_VERSION {
            return Err(TelemetryError::UnsupportedVersion {
                actual: json.version,
            });
        }
        Ok(Self {
            magic: json.magic,
            version: json.version,
            flags: json.flags,
            mod_id: json.mod_id,
            system_hash: json.system_hash,
            frame_seq: json.frame_seq,
            matched_entities: json.matched_entities,
            matched_tables: json.matched_tables,
            skipped_summary_tick_tables: json.skipped_summary_tick_tables,
            chunks: json.chunks,
            p50_us: json.p50_us,
            p99_us: json.p99_us,
            commands_queued: json.commands_queued,
            reserved: json.reserved,
        })
    }
}

/// Errors emitted while validating binary `SystemTelemetryDigest64` frames or `bam/*` BRP payloads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TelemetryError {
    /// Binary packet length did not equal 64 bytes.
    #[error(
        "invalid SystemTelemetryDigest64 length {actual} (expected {SYSTEM_TELEMETRY_DIGEST_SIZE})"
    )]
    InvalidLength {
        /// Actual byte count received.
        actual: usize,
    },
    /// Packet magic header did not equal `b"BAMT"`.
    #[error("invalid telemetry magic {actual:?} (expected b\"BAMT\")")]
    InvalidMagic {
        /// Actual 4-byte magic prefix read from offset 0.
        actual: [u8; 4],
    },
    /// Packet wire version is not supported.
    #[error(
        "unsupported telemetry digest version {actual} (expected {SYSTEM_TELEMETRY_DIGEST_VERSION})"
    )]
    UnsupportedVersion {
        /// Actual wire version read from offset 4.
        actual: u16,
    },
    /// BRP JSON-RPC payload was malformed or contained a JSON-RPC error response.
    #[error("invalid BRP payload: {0}")]
    InvalidBrpJson(String),
    /// Network or socket I/O error communicating with a BRP / telemetry endpoint.
    #[error("telemetry transport I/O error: {0}")]
    Io(String),
}

impl From<TelemetryFrameError> for TelemetryError {
    fn from(err: TelemetryFrameError) -> Self {
        match err {
            TelemetryFrameError::InvalidMagic(actual) => Self::InvalidMagic { actual },
            TelemetryFrameError::UnsupportedVersion(actual) => Self::UnsupportedVersion { actual },
        }
    }
}

impl From<TelemetrySliceError> for TelemetryError {
    fn from(err: TelemetrySliceError) -> Self {
        match err {
            TelemetrySliceError::InvalidLength(actual) => Self::InvalidLength { actual },
            TelemetrySliceError::Frame(frame) => Self::from(frame),
        }
    }
}

/// Decodes and validates a canonical 64-byte little-endian [`SystemTelemetryDigest64`] wire packet.
pub fn decode_digest_slice(bytes: &[u8]) -> Result<SystemTelemetryDigest64, TelemetryError> {
    SystemTelemetryDigest64::from_le_slice(bytes).map_err(TelemetryError::from)
}

/// Builds a canonical valid [`SystemTelemetryDigest64`] frame for a given `(mod_name, system_name)`
/// using [`fnv1a_64_hash_system`].
#[must_use]
pub const fn new_digest(mod_id: u64, system_hash: u64, frame_seq: u64) -> SystemTelemetryDigest64 {
    SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id,
        system_hash,
        frame_seq,
        matched_entities: 0,
        matched_tables: 0,
        skipped_summary_tick_tables: 0,
        chunks: 0,
        p50_us: 0,
        p99_us: 0,
        commands_queued: 0,
        reserved: 0,
    }
}

/// Computes the deterministic 64-bit FNV-1a system identifier hash matching [`fnv1a_64_str`].
/// When given `"{mod_name}::{system_name}"`, this is bit-for-bit identical to
/// [`fnv1a_64_hash_system`]`(mod_name, system_name)`.
#[must_use]
pub const fn system_name_hash(name: &str) -> u64 {
    fnv1a_64_str(name)
}

/// One component/resource schema entry returned by BRP `bam/component_schemas`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrpSchemaEntry {
    /// Canonical component or resource name (e.g. `combat::Health` or `Health`).
    #[serde(alias = "name", alias = "type_name")]
    pub canonical_name: String,
    /// ABI byte size reported by the host runtime (`0` if unsized/unspecified).
    #[serde(default)]
    pub size: u32,
    /// ABI alignment reported by the host runtime (`0` if unspecified).
    #[serde(default)]
    pub align: u16,
    /// 128-bit `ComponentUuid` / SipHash24 identifier if reported by the host runtime.
    #[serde(default)]
    pub uuid: u128,
    /// Whether the host registered this component as ABI POD (`true`) or opaque.
    #[serde(default, alias = "is_abi_pod")]
    pub is_pod: bool,
}

fn parse_uuid_value(v: &Value) -> Option<u128> {
    if let Some(n) = v.as_u64() {
        return Some(u128::from(n));
    }
    if let Some(s) = v.as_str() {
        let trimmed = s.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return u128::from_str_radix(hex, 16).ok();
        }
        return trimmed.parse::<u128>().ok();
    }
    None
}

fn parse_schema_array(arr: &[Value]) -> Result<Vec<BrpSchemaEntry>, TelemetryError> {
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item.as_object().ok_or_else(|| {
            TelemetryError::InvalidBrpJson("BRP schema entry must be a JSON object".to_owned())
        })?;
        let canonical_name = obj
            .get("name")
            .or_else(|| obj.get("canonical_name"))
            .or_else(|| obj.get("type_name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TelemetryError::InvalidBrpJson(
                    "BRP schema entry missing `name` / `canonical_name` field".to_owned(),
                )
            })?
            .to_owned();
        let size = obj
            .get("size")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        let align = obj
            .get("align")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0);
        let uuid = obj.get("uuid").and_then(parse_uuid_value).unwrap_or(0);
        let is_pod = obj
            .get("is_pod")
            .or_else(|| obj.get("is_abi_pod"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        out.push(BrpSchemaEntry {
            canonical_name,
            size,
            align,
            uuid,
            is_pod,
        });
    }
    Ok(out)
}

/// Parses a `bam/component_schemas` BRP JSON-RPC response payload.
///
/// Supports:
/// - Canonical `result.components[]` (`components[].name`, `size`, `align`, `uuid`, `is_pod`)
/// - Legacy `result.schemas[]` (`canonical_name`, `size`, `align`, `uuid`, `is_pod`)
/// - Direct JSON arrays in `result` (`result: [...]`).
pub fn parse_brp_schema_json(payload: &str) -> Result<Vec<BrpSchemaEntry>, TelemetryError> {
    let root: Value =
        serde_json::from_str(payload).map_err(|e| TelemetryError::InvalidBrpJson(e.to_string()))?;

    if let Some(err) = root.get("error") {
        return Err(TelemetryError::InvalidBrpJson(format!(
            "BRP error response: {err}"
        )));
    }

    let result = root.get("result").unwrap_or(&root);

    if let Some(arr) = result.as_array() {
        return parse_schema_array(arr);
    }

    if let Some(list) = result.get("components").and_then(|v| v.as_array()) {
        return parse_schema_array(list);
    }

    if let Some(list) = result.get("schemas").and_then(|v| v.as_array()) {
        return parse_schema_array(list);
    }

    Err(TelemetryError::InvalidBrpJson(
        "expected BRP `result` array or `result.components` / `result.schemas` field".to_owned(),
    ))
}

/// Thread-safe store holding latest monotonic [`SystemTelemetryDigest64`] samples keyed by
/// `system_hash` together with ingested BRP component schemas.
#[derive(Debug, Clone, Default)]
pub struct TelemetryStore {
    inner: Arc<RwLock<TelemetryInner>>,
}

#[derive(Debug, Default)]
struct TelemetryInner {
    by_hash: BTreeMap<u64, SystemTelemetryDigest64>,
    schemas: BTreeMap<String, BrpSchemaEntry>,
}

fn insert_if_newer(guard: &mut TelemetryInner, digest: SystemTelemetryDigest64) {
    match guard.by_hash.get_mut(&digest.system_hash) {
        Some(existing) if existing.frame_seq > digest.frame_seq => {}
        Some(existing) => *existing = digest,
        None => {
            guard.by_hash.insert(digest.system_hash, digest);
        }
    }
}

impl TelemetryStore {
    /// Creates an empty [`TelemetryStore`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests one raw 64-byte [`SystemTelemetryDigest64`] wire packet, preserving monotonic
    /// `frame_seq` ordering per `system_hash`.
    pub fn ingest_digest_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<SystemTelemetryDigest64, TelemetryError> {
        let digest = decode_digest_slice(bytes)?;
        self.record_digest(digest);
        Ok(digest)
    }

    /// Records a [`SystemTelemetryDigest64`] directly, preserving monotonic `frame_seq`
    /// ordering per `system_hash`.
    pub fn record_digest(&self, digest: SystemTelemetryDigest64) {
        if let Ok(mut guard) = self.inner.write() {
            insert_if_newer(&mut guard, digest);
        }
    }

    /// Records multiple [`SystemTelemetryDigest64`] frames atomically under a single write lock,
    /// ignoring stale out-of-order `frame_seq` packets per `system_hash`.
    pub fn record_digests(&self, digests: impl IntoIterator<Item = SystemTelemetryDigest64>) {
        if let Ok(mut guard) = self.inner.write() {
            for digest in digests {
                insert_if_newer(&mut guard, digest);
            }
        }
    }

    /// Looks up the latest digest matching a canonical or short system name via FNV-1a hash.
    /// When `name` is `"{mod}::{sys}"`, [`fnv1a_64_str`] matches [`fnv1a_64_hash_system(mod, sys)`].
    pub fn get_for_system(&self, name: &str) -> Option<SystemTelemetryDigest64> {
        let hash = fnv1a_64_str(name);
        if let Ok(guard) = self.inner.read() {
            if let Some(d) = guard.by_hash.get(&hash).copied() {
                return Some(d);
            }
            // Fallback: allow unscoped `"{}::{name}"` if caller queried short name only.
            let empty_mod_hash = fnv1a_64_hash_system("", name);
            guard.by_hash.get(&empty_mod_hash).copied()
        } else {
            None
        }
    }

    /// Looks up the latest digest matching a graph node (`canonical_id` first, then `short_name`).
    /// Also checks `fnv1a_64_hash_system(mod_part, sys_part)` and `fnv1a_64_hash_system("", short)`.
    /// Returns `(digest, matched_key_label)` where `matched_key_label` is `"canonical"` or `"bare"`.
    pub fn get_for_node(
        &self,
        canonical_id: &str,
        short_name: Option<&str>,
    ) -> Option<(SystemTelemetryDigest64, &'static str)> {
        let Ok(guard) = self.inner.read() else {
            return None;
        };
        let canon_hash = fnv1a_64_str(canonical_id);
        if let Some(d) = guard.by_hash.get(&canon_hash).copied() {
            return Some((d, "canonical"));
        }
        if let Some((mod_part, sys_part)) = canonical_id.rsplit_once("::") {
            let split_hash = fnv1a_64_hash_system(mod_part, sys_part);
            if let Some(d) = guard.by_hash.get(&split_hash).copied() {
                return Some((d, "canonical"));
            }
        }
        if let Some(short) = short_name {
            let short_hash = fnv1a_64_str(short);
            if let Some(d) = guard.by_hash.get(&short_hash).copied() {
                return Some((d, "bare"));
            }
            let empty_mod_hash = fnv1a_64_hash_system("", short);
            if let Some(d) = guard.by_hash.get(&empty_mod_hash).copied() {
                return Some((d, "bare"));
            }
        }
        None
    }

    /// Parses and merges schemas from a `bam/component_schemas` BRP JSON-RPC payload.
    pub fn ingest_brp_json(&self, json: &str) -> Result<usize, TelemetryError> {
        let entries = parse_brp_schema_json(json)?;
        let count = entries.len();
        if let Ok(mut guard) = self.inner.write() {
            for entry in entries {
                guard.schemas.insert(entry.canonical_name.clone(), entry);
            }
        }
        Ok(count)
    }

    /// Looks up a previously ingested BRP component schema by canonical (or short) name.
    pub fn get_schema(&self, canonical_name: &str) -> Option<BrpSchemaEntry> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.schemas.get(canonical_name).cloned())
    }

    /// Returns the total number of distinct component schemas stored from BRP.
    pub fn schema_count(&self) -> usize {
        self.inner.read().map_or(0, |g| g.schemas.len())
    }
}

/// Transport endpoint for live 64-byte [`SystemTelemetryDigest64`] IPC frame streaming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryEndpoint {
    /// Unix domain stream socket (`AF_UNIX`), preferred on macOS/Linux.
    Unix(PathBuf),
    /// Loopback/network TCP stream socket (`TcpStream`).
    Tcp(SocketAddr),
}

/// Handle controlling a background non-blocking [`TelemetryEndpoint`] subscriber task.
#[derive(Debug)]
pub struct TelemetrySubscription {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl TelemetrySubscription {
    /// Signals the background subscriber to stop and awaits its clean termination.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }

    /// Requests background subscriber termination without blocking.
    pub fn signal_stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

async fn pump_stream<R>(
    mut reader: R,
    store: &TelemetryStore,
    shutdown_rx: &mut watch::Receiver<bool>,
) where
    R: AsyncReadExt + Unpin,
{
    let mut buf = [0u8; SYSTEM_TELEMETRY_DIGEST_SIZE];
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
            res = reader.read_exact(&mut buf) => {
                match res {
                    Ok(_) => {
                        let _ = store.ingest_digest_bytes(&buf);
                    }
                    Err(_) => return,
                }
            }
        }
    }
}

/// Spawns a non-blocking `tokio` background subscriber reading raw 64-byte `"BAMT"`
/// [`SystemTelemetryDigest64`] frames from `endpoint` into `store`.
pub fn spawn_telemetry_subscriber(
    endpoint: TelemetryEndpoint,
    store: TelemetryStore,
) -> TelemetrySubscription {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            match &endpoint {
                TelemetryEndpoint::Unix(path) => {
                    let connect = tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        res = UnixStream::connect(path) => res,
                    };
                    if let Ok(stream) = connect {
                        pump_stream(stream, &store, &mut shutdown_rx).await;
                    }
                }
                TelemetryEndpoint::Tcp(addr) => {
                    let connect = tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        res = TcpStream::connect(addr) => res,
                    };
                    if let Ok(stream) = connect {
                        pump_stream(stream, &store, &mut shutdown_rx).await;
                    }
                }
            }
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    });
    TelemetrySubscription { shutdown_tx, task }
}

fn decode_http_chunked(raw: &str) -> Result<String, TelemetryError> {
    let mut out = String::new();
    let mut rest = raw;
    loop {
        let Some((size_line, after_line)) = rest.split_once("\r\n") else {
            return Err(TelemetryError::InvalidBrpJson(
                "malformed chunked HTTP body from BRP endpoint".to_owned(),
            ));
        };
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|e| {
            TelemetryError::InvalidBrpJson(format!("invalid HTTP chunk length `{hex_part}`: {e}"))
        })?;
        if chunk_len == 0 {
            break;
        }
        if after_line.len() < chunk_len + 2 {
            return Err(TelemetryError::InvalidBrpJson(
                "truncated HTTP chunk body from BRP endpoint".to_owned(),
            ));
        }
        out.push_str(&after_line[..chunk_len]);
        rest = &after_line[chunk_len + 2..];
    }
    Ok(out)
}

/// Sends a JSON-RPC `bam/component_schemas` HTTP/1.1 request to a Bevy Remote Protocol (`BRP`)
/// endpoint over [`TcpStream`] and parses the returned component schemas.
pub async fn fetch_brp_component_schemas(
    addr: SocketAddr,
) -> Result<Vec<BrpSchemaEntry>, TelemetryError> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| TelemetryError::Io(e.to_string()))?;

    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": BRP_METHOD_BAM_COMPONENT_SCHEMAS,
        "params": {}
    })
    .to_string();

    let http_req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rpc_body}",
        rpc_body.len()
    );

    stream
        .write_all(http_req.as_bytes())
        .await
        .map_err(|e| TelemetryError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| TelemetryError::Io(e.to_string()))?;

    let mut raw_resp = Vec::new();
    stream
        .read_to_end(&mut raw_resp)
        .await
        .map_err(|e| TelemetryError::Io(e.to_string()))?;

    let text = String::from_utf8(raw_resp).map_err(|e| {
        TelemetryError::InvalidBrpJson(format!("non-UTF-8 HTTP response from BRP endpoint: {e}"))
    })?;

    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| {
            TelemetryError::InvalidBrpJson("HTTP response missing header/body separator".to_owned())
        })?;

    let status_line = head.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            TelemetryError::InvalidBrpJson(format!("malformed HTTP status line `{status_line}`"))
        })?;
    if !(200..300).contains(&status_code) {
        return Err(TelemetryError::InvalidBrpJson(format!(
            "BRP HTTP error status {status_code}: {body}"
        )));
    }

    let is_chunked = head.lines().any(|l| {
        l.to_ascii_lowercase().contains("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let json_payload = if is_chunked {
        decode_http_chunked(body)?
    } else {
        body.to_owned()
    };

    parse_brp_schema_json(&json_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codec_rejects_bad_length_magic_version_and_brp() {
        assert_eq!(
            decode_digest_slice(&[0u8; 63]),
            Err(TelemetryError::InvalidLength { actual: 63 })
        );
        let mut bad_magic = new_digest(1, fnv1a_64_hash_system("combat", "tick"), 7).to_le_bytes();
        bad_magic[0..4].copy_from_slice(b"NOPE");
        assert_eq!(
            decode_digest_slice(&bad_magic),
            Err(TelemetryError::InvalidMagic { actual: *b"NOPE" })
        );

        let mut bad_ver = new_digest(1, fnv1a_64_hash_system("combat", "tick"), 7).to_le_bytes();
        bad_ver[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode_digest_slice(&bad_ver),
            Err(TelemetryError::UnsupportedVersion { actual: 99 })
        );

        let err = parse_brp_schema_json(r#"{"jsonrpc":"2.0","error":{"code":-32601}}"#)
            .expect_err("error payload must be rejected");
        assert!(matches!(err, TelemetryError::InvalidBrpJson(_)));
    }

    #[test]
    fn telemetry_store_round_trips_bamt_digest_and_components_brp() {
        let store = TelemetryStore::new();
        let digest = SystemTelemetryDigest64 {
            magic: SYSTEM_TELEMETRY_MAGIC,
            version: SYSTEM_TELEMETRY_DIGEST_VERSION,
            flags: TELEMETRY_FLAG_SUMMARY_TICK_ACTIVE,
            mod_id: 7,
            system_hash: fnv1a_64_hash_system("game::physics", "integrate"),
            frame_seq: 42,
            matched_entities: 500,
            matched_tables: 12,
            skipped_summary_tick_tables: 4,
            chunks: 8,
            p50_us: 320,
            p99_us: 610,
            commands_queued: 3,
            reserved: 0,
        };
        let bytes = digest.to_le_bytes();
        let decoded = store
            .ingest_digest_bytes(&bytes)
            .expect("valid 64-byte BAMT frame");
        assert_eq!(decoded, digest);
        assert_eq!(
            store.get_for_node("game::physics::integrate", Some("integrate")),
            Some((digest, "canonical"))
        );

        let brp = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "components": [
                    { "name": "game::physics::Pos", "size": 12, "align": 4, "uuid": "0x2a", "is_pod": true }
                ]
            }
        }"#;
        assert_eq!(store.ingest_brp_json(brp).expect("BRP ingest"), 1);
        let schema = store
            .get_schema("game::physics::Pos")
            .expect("schema stored");
        assert_eq!(schema.size, 12);
        assert_eq!(schema.align, 4);
        assert_eq!(schema.uuid, 42);
        assert!(schema.is_pod);
    }

    #[test]
    fn telemetry_store_enforces_monotonic_frame_seq_ordering() {
        let store = TelemetryStore::new();
        let make =
            |mod_name: &str, sys_name: &str, frame_seq: u64, p50_us: u32| SystemTelemetryDigest64 {
                magic: SYSTEM_TELEMETRY_MAGIC,
                version: SYSTEM_TELEMETRY_DIGEST_VERSION,
                flags: 0,
                mod_id: 1,
                system_hash: fnv1a_64_hash_system(mod_name, sys_name),
                frame_seq,
                matched_entities: 100,
                matched_tables: 3,
                skipped_summary_tick_tables: 1,
                chunks: 2,
                p50_us,
                p99_us: p50_us * 2,
                commands_queued: 0,
                reserved: 0,
            };

        store.record_digests([
            make("test::mod", "move_sys", 10, 120),
            make("test::mod", "move_sys", 42, 420),
            make("test::mod", "move_sys", 25, 250),
        ]);

        let recorded = store
            .get_for_system("test::mod::move_sys")
            .expect("frame should be recorded");
        assert_eq!(recorded.frame_seq, 42);
        assert_eq!(recorded.p50_us, 420);
    }
}
