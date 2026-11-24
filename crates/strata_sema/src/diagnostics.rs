//! Machine-readable JSON diagnostics and fix-its for Strata v2.0 (`E01xx..E06xx`, `W04xx`).

use serde::{Deserialize, Serialize};
use strata_syntax::{TextRange, TextSize};

/// Diagnostic severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Hard compilation error.
    Error,
    /// Non-fatal AI-native anti-pattern or style warning.
    Warning,
    /// Informational diagnostic.
    Info,
}

/// Source span with 1-based line/column and UTF-8 byte offsets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// Logical file name or module identifier.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based UTF-8 column number.
    pub col: u32,
    /// 0-based inclusive start byte offset.
    pub byte_start: u32,
    /// 0-based exclusive end byte offset.
    pub byte_end: u32,
}

impl Span {
    /// Computes a [`Span`] from source text and a `rowan::TextRange`.
    pub fn from_range(file: impl Into<String>, src: &str, range: TextRange) -> Self {
        let start = usize::min(u32::from(range.start()) as usize, src.len());
        let end = usize::min(u32::from(range.end()) as usize, src.len());
        let prefix = &src[..start];
        let line = prefix.bytes().filter(|&b| b == b'\n').count() as u32 + 1;
        let last_nl = prefix.rfind('\n').map_or(0, |idx| idx + 1);
        let col = prefix[last_nl..].chars().count() as u32 + 1;
        Self {
            file: file.into(),
            line,
            col,
            byte_start: start as u32,
            byte_end: end as u32,
        }
    }

    /// Computes a [`Span`] from raw byte offsets `[byte_start, byte_end)`.
    pub fn from_bytes(file: impl Into<String>, src: &str, byte_start: u32, byte_end: u32) -> Self {
        let range = TextRange::new(TextSize::from(byte_start), TextSize::from(byte_end));
        Self::from_range(file, src, range)
    }
}

/// Machine-applicable patch suggestion for automated tool/LLM repair loops.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FixIt {
    /// Inclusive start byte offset to replace.
    pub replace_byte_start: u32,
    /// Exclusive end byte offset to replace.
    pub replace_byte_end: u32,
    /// Replacement source snippet.
    pub replacement: String,
}

/// Structured compiler diagnostic emitted by `strata_sema` and `stratac check --format=json`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Canonical diagnostic identifier (e.g. `"E0201_ALIASING_CONFLICT"`).
    pub code: String,
    /// Severity level.
    pub severity: Severity,
    /// Source span.
    pub span: Span,
    /// Human-readable message explaining the invariant violation.
    pub message: String,
    /// Optional machine-applicable fix-it patch.
    pub fixit: Option<FixIt>,
}

impl Diagnostic {
    /// Creates an error diagnostic.
    pub fn error(
        code: impl Into<String>,
        span: Span,
        message: impl Into<String>,
        fixit: Option<FixIt>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            span,
            message: message.into(),
            fixit,
        }
    }

    /// Creates a warning diagnostic.
    pub fn warning(
        code: impl Into<String>,
        span: Span,
        message: impl Into<String>,
        fixit: Option<FixIt>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            span,
            message: message.into(),
            fixit,
        }
    }
}

// --- Canonical Diagnostic Codes ---
#[allow(missing_docs)]
pub mod codes {
    pub const E0001_LEX_ERROR: &str = "E0001_LEX_ERROR";
    pub const E0002_PARSE_ERROR: &str = "E0002_PARSE_ERROR";
    pub const E0101_UNKNOWN_TYPE: &str = "E0101_UNKNOWN_TYPE";
    pub const E0102_UNIT_MISMATCH: &str = "E0102_UNIT_MISMATCH";
    pub const E0103_INVALID_ABI_POD_FIELD: &str = "E0103_INVALID_ABI_POD_FIELD";
    pub const E0104_PADDING_HAZARD: &str = "E0104_PADDING_HAZARD";
    pub const E0105_ASSERT_LAYOUT_FAILED: &str = "E0105_ASSERT_LAYOUT_FAILED";
    pub const E0106_TABLE_NOT_EXHAUSTIVE: &str = "E0106_TABLE_NOT_EXHAUSTIVE";
    pub const E0107_CURVE_NON_MONOTONIC: &str = "E0107_CURVE_NON_MONOTONIC";
    pub const E0108_TIMELINE_INVALID_WINDOW: &str = "E0108_TIMELINE_INVALID_WINDOW";
    pub const E0109_FSM_INVALID_TARGET: &str = "E0109_FSM_INVALID_TARGET";
    pub const E0110_SPARSE_SUMMARY_TICK: &str = "E0110_SPARSE_SUMMARY_TICK";
    pub const E0111_TYPE_MISMATCH: &str = "E0111_TYPE_MISMATCH";
    pub const E0201_ALIASING_CONFLICT: &str = "E0201_ALIASING_CONFLICT";
    pub const E0202_ASSERT_PAR_FAILED: &str = "E0202_ASSERT_PAR_FAILED";
    pub const E0203_QUERY_LIMIT_EXCEEDED: &str = "E0203_QUERY_LIMIT_EXCEEDED";
    pub const E0204_EFFECTS_MISMATCH: &str = "E0204_EFFECTS_MISMATCH";
    pub const E0301_UNRESOLVED_SYMBOL: &str = "E0301_UNRESOLVED_SYMBOL";
    pub const E0302_NON_POD_ACROSS_WAIT: &str = "E0302_NON_POD_ACROSS_WAIT";
    pub const E0303_DUPLICATE_SYMBOL: &str = "E0303_DUPLICATE_SYMBOL";
    pub const E0501_AUTHORITY_VIOLATION: &str = "E0501_AUTHORITY_VIOLATION";
    pub const E0502_INVALID_NET_ATTR: &str = "E0502_INVALID_NET_ATTR";
    pub const E0503_INVALID_QUANTIZE: &str = "E0503_INVALID_QUANTIZE";
    pub const E0504_INVALID_AUTHORITY: &str = "E0504_INVALID_AUTHORITY";
    pub const E0505_INVALID_NET_SIM_PARAM: &str = "E0505_INVALID_NET_SIM_PARAM";
    pub const E0601_NODE_PURE_VIOLATION: &str = "E0601_NODE_PURE_VIOLATION";
    pub const E0602_INVALID_NODE_GROUP: &str = "E0602_INVALID_NODE_GROUP";
    pub const W0401_QUADRATIC_NESTED_QUERY: &str = "W0401_QUADRATIC_NESTED_QUERY";
    pub const W0402_USE_SELECTIVE_MUT_TICK: &str = "W0402_USE_SELECTIVE_MUT_TICK";
    pub const W0403_USE_SPAWN_BATCH: &str = "W0403_USE_SPAWN_BATCH";
    pub const W0404_LARGE_AOS_COMPONENT_SPLIT_SOA: &str = "W0404_LARGE_AOS_COMPONENT_SPLIT_SOA";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies byte-span line/column mapping handles multi-line sources and clamped EOF bounds.
    #[test]
    fn span_from_bytes_resolves_one_based_line_and_col() {
        let src = "line one\nline two\n";
        let span = Span::from_bytes("test.strata", src, 9, 13);
        assert_eq!(span.line, 2);
        assert_eq!(span.col, 1);
        let eof = Span::from_bytes("test.strata", src, 999, 999);
        assert_eq!(eof.byte_start as usize, src.len());
        assert_eq!(eof.byte_end as usize, src.len());
    }
}
