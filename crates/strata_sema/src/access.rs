//! Theorem 0.1 `FilteredAccessSet` disjointness prover, intra-system aliasing checker,
//! `bamabi_sys` query limit enforcement, and `ConcurrencyGraph` builder.

use crate::diagnostics::{Diagnostic, FixIt, Span, codes};
use bamabi_sys::{MAX_QUERIES_PER_SYSTEM, MAX_TERMS_PER_QUERY};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Access mode for a single query term or system parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum TermAccessMode {
    Read,
    Write,
    SelectiveWrite,
    OptionalRead,
    OptionalWrite,
    With,
    Without,
    Allow,
    Has,
    RemovedRead,
    ResRead,
    ResWrite,
    StreamRead,
    StreamWrite,
}

impl TermAccessMode {
    /// Returns `true` if this access mutates component, resource, or stream storage.
    #[inline]
    pub const fn is_mutable(self) -> bool {
        matches!(
            self,
            Self::Write
                | Self::SelectiveWrite
                | Self::OptionalWrite
                | Self::ResWrite
                | Self::StreamWrite
        )
    }

    /// Returns `true` if this access borrows entity component data (`Read`/`Write`/optional).
    #[inline]
    pub const fn accesses_component_data(self) -> bool {
        matches!(
            self,
            Self::Read
                | Self::Write
                | Self::SelectiveWrite
                | Self::OptionalRead
                | Self::OptionalWrite
        )
    }
}

/// One resolved query term targeting a component/stratum and optional sub-field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryTerm {
    /// Logical component or `@soa` stratum key (e.g. `"CombatantBody::hot"` or `"Pos3D"`).
    pub storage_key: String,
    /// Optional projected field name (e.g. `Some("hp")`). `None` borrows the whole storage unit.
    pub field_name: Option<String>,
    /// Borrow mode.
    pub mode: TermAccessMode,
    /// Byte span in source for diagnostics.
    pub byte_start: u32,
    /// Byte end in source for diagnostics.
    pub byte_end: u32,
}

/// One `query(...)` or `query_one(...)` access signature inside a system/observer/task.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct QueryAccessDesc {
    /// Ordered query terms.
    pub terms: Vec<QueryTerm>,
    /// `With<T>` archetype inclusion filters.
    pub with_filters: BTreeSet<String>,
    /// `Without<T>` archetype exclusion filters.
    pub without_filters: BTreeSet<String>,
    /// `true` when this descriptor comes from a `task`'s `on (...)` header.
    pub is_task_on_header: bool,
    /// `true` when this query is a single-entity `.on(id)` point lookup.
    pub is_point_lookup: bool,
    /// Source span of the query call.
    pub byte_start: u32,
    /// Source span end of the query call.
    pub byte_end: u32,
}

impl QueryAccessDesc {
    /// Returns `true` iff `self` and `other` cannot match any shared archetype due to complementary
    /// `With<X>` / `Without<X>` filters (Theorem 0.1 archetype disjointness).
    pub fn is_archetype_disjoint_from(&self, other: &Self) -> bool {
        !self.with_filters.is_disjoint(&other.without_filters)
            || !other.with_filters.is_disjoint(&self.without_filters)
    }

    /// Returns conflicting component storage keys between `self` and `other`, respecting
    /// Theorem 0.1 `With`/`Without` archetype disjointness.
    pub fn conflicting_storages_with(&self, other: &Self) -> Vec<String> {
        if self.is_archetype_disjoint_from(other) {
            return Vec::new();
        }
        let mut conflicts = Vec::new();
        for ta in &self.terms {
            if !ta.mode.accesses_component_data() {
                continue;
            }
            for tb in &other.terms {
                if !tb.mode.accesses_component_data() {
                    continue;
                }
                if (ta.mode.is_mutable() || tb.mode.is_mutable())
                    && storage_keys_overlap(&ta.storage_key, &tb.storage_key)
                {
                    let label = if ta.storage_key == tb.storage_key {
                        ta.storage_key.clone()
                    } else {
                        format!("{} / {}", ta.storage_key, tb.storage_key)
                    };
                    if !conflicts.contains(&label) {
                        conflicts.push(label);
                    }
                }
            }
        }
        conflicts
    }
}

/// Complete `FilteredAccessSet` summary for one system, observer, or synthesized state-machine tick.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct FilteredAccessSet {
    /// System or task name.
    pub system_name: String,
    /// Queries executed by this system.
    pub queries: Vec<QueryAccessDesc>,
    /// Singleton resources read (`&res R`).
    pub res_reads: BTreeSet<String>,
    /// Singleton resources mutated (`&mut res R`).
    pub res_writes: BTreeSet<String>,
    /// Buffered streams read (`stream_in<S>`).
    pub stream_reads: BTreeSet<String>,
    /// Buffered streams emitted (`emit(S { ... })`).
    pub stream_writes: BTreeSet<String>,
    /// `true` if `@par(...)` was attached.
    pub is_par: bool,
    /// `true` if `@par(read_only, ...)` was attached.
    pub is_read_only_par: bool,
}

/// Reason two systems must serialize instead of running in parallel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConflictEdge {
    /// First system name.
    pub system_a: String,
    /// Second system name.
    pub system_b: String,
    /// Conflicting resource/component/stream descriptions.
    pub reasons: Vec<String>,
}

/// Full system-to-system parallelism / conflict graph emitted for `stratac explain-par`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConcurrencyGraph {
    /// All analyzed system/task names.
    pub systems: Vec<String>,
    /// Serialization edges (`reasons` explains each conflict).
    pub conflicts: Vec<ConflictEdge>,
}

/// Checks whether two component/stratum keys alias (`"Pos3D"` aliases `"Pos3D"`, and unsplit
/// `"CombatantBody"` aliases `"CombatantBody::hot"`, while `"CombatantBody::hot"` and
/// `"CombatantBody::caps"` are disjoint).
pub fn storage_keys_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (a.split_once("::"), b.split_once("::")) {
        (Some((base_a, _)), None) => base_a == b,
        (None, Some((base_b, _))) => a == base_b,
        _ => false,
    }
}

/// Checks whether two terms inside the *same* `query(...)` alias the same memory location.
///
/// Projecting distinct fields of one component/stratum (`&mut CombatantBody.hp, &mut CombatantBody.poise`)
/// is non-aliasing, while projecting overlapping fields or mixing a whole-struct borrow with a
/// field borrow conflicts.
fn intra_query_terms_conflict(a: &QueryTerm, b: &QueryTerm) -> bool {
    if !a.mode.accesses_component_data() || !b.mode.accesses_component_data() {
        return false;
    }
    if !(a.mode.is_mutable() || b.mode.is_mutable()) {
        return false;
    }
    if !storage_keys_overlap(&a.storage_key, &b.storage_key) {
        return false;
    }
    match (&a.field_name, &b.field_name) {
        (Some(fa), Some(fb)) => fa == fb,
        _ => true,
    }
}

/// Validates intra-system borrow safety and `bamabi_sys` query limits (`MAX_TERMS_PER_QUERY`,
/// `MAX_QUERIES_PER_SYSTEM`), returning diagnostics for any conflicts.
pub fn validate_system_accesses(
    file: &str,
    src: &str,
    access: &FilteredAccessSet,
    sys_span: (u32, u32),
) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    if access.queries.len() > MAX_QUERIES_PER_SYSTEM {
        diags.push(Diagnostic::error(
            codes::E0203_QUERY_LIMIT_EXCEEDED,
            Span::from_bytes(file, src, sys_span.0, sys_span.1),
            format!(
                "system `{}` uses {} queries, exceeding bamabi_sys::MAX_QUERIES_PER_SYSTEM ({})",
                access.system_name,
                access.queries.len(),
                MAX_QUERIES_PER_SYSTEM
            ),
            None,
        ));
    }

    // Intra-query aliasing and per-query term limit.
    for q in &access.queries {
        let total_terms = q.terms.len() + q.with_filters.len() + q.without_filters.len();
        if total_terms > MAX_TERMS_PER_QUERY {
            diags.push(Diagnostic::error(
                codes::E0203_QUERY_LIMIT_EXCEEDED,
                Span::from_bytes(file, src, q.byte_start, q.byte_end),
                format!(
                    "query in `{}` has {} terms, exceeding bamabi_sys::MAX_TERMS_PER_QUERY ({})",
                    access.system_name, total_terms, MAX_TERMS_PER_QUERY
                ),
                None,
            ));
        }

        for i in 0..q.terms.len() {
            for j in (i + 1)..q.terms.len() {
                if intra_query_terms_conflict(&q.terms[i], &q.terms[j]) {
                    let fixit = Some(FixIt {
                        replace_byte_start: q.terms[j].byte_start,
                        replace_byte_end: q.terms[j].byte_end,
                        replacement: format!(
                            "/* remove conflicting alias `{}` */",
                            q.terms[j].storage_key
                        ),
                    });
                    diags.push(Diagnostic::error(
                        codes::E0201_ALIASING_CONFLICT,
                        Span::from_bytes(file, src, q.terms[j].byte_start, q.terms[j].byte_end),
                        format!(
                            "intra-query aliasing conflict in `{}`: `{}` conflicts with earlier borrow",
                            access.system_name, q.terms[j].storage_key
                        ),
                        fixit,
                    ));
                }
            }
        }
    }

    // Inter-query aliasing within the same system (Theorem 0.1 disjointness check).
    for i in 0..access.queries.len() {
        for j in (i + 1)..access.queries.len() {
            let qa = &access.queries[i];
            let qb = &access.queries[j];
            // A `task` coroutine's `on(...)` header fields are copied before suspension points
            // (`wait`/`race`), so sequential `.on(target)` point lookups inside a task step do not
            // hold concurrent chunk aliases with `on(...)`.
            if (qa.is_task_on_header && qb.is_point_lookup)
                || (qb.is_task_on_header && qa.is_point_lookup)
            {
                continue;
            }
            let conflicts = qa.conflicting_storages_with(qb);
            if !conflicts.is_empty() {
                diags.push(Diagnostic::error(
                    codes::E0201_ALIASING_CONFLICT,
                    Span::from_bytes(file, src, qb.byte_start, qb.byte_end),
                    format!(
                        "intra-system query aliasing conflict in `{}` on `{}` without With<T>/Without<T> disjointness",
                        access.system_name,
                        conflicts.join(", ")
                    ),
                    None,
                ));
            }
        }
    }

    diags
}

/// Returns `true` iff two data-access modes conflict (both access component storage and at least
/// one is mutable). Symmetric in `(a, b)`.
#[inline]
#[must_use]
pub const fn modes_conflict(a: TermAccessMode, b: TermAccessMode) -> bool {
    a.accesses_component_data() && b.accesses_component_data() && (a.is_mutable() || b.is_mutable())
}

/// Bitmask encoding of Theorem 0.1 archetype filter disjointness (`With<X>` vs `Without<X>` across
/// up to 8 components encoded as bit positions `0..8`).
#[inline]
#[must_use]
pub const fn archetype_masks_disjoint(
    with_a: u8,
    without_a: u8,
    with_b: u8,
    without_b: u8,
) -> bool {
    (with_a & without_b) != 0 || (with_b & without_a) != 0
}

/// Computes serialization reasons between two systems under Theorem 0.1 (`FilteredAccessSet`).
///
/// An empty vector means `a` and `b` are provably parallel-safe.
pub fn system_conflicts(a: &FilteredAccessSet, b: &FilteredAccessSet) -> Vec<String> {
    let mut reasons = Vec::new();

    for r in &a.res_writes {
        if b.res_reads.contains(r) || b.res_writes.contains(r) {
            reasons.push(format!("resource `{r}` (write in `{}`)", a.system_name));
        }
    }
    for r in &b.res_writes {
        if a.res_reads.contains(r) && !a.res_writes.contains(r) {
            reasons.push(format!("resource `{r}` (write in `{}`)", b.system_name));
        }
    }
    for s in &a.stream_writes {
        if b.stream_reads.contains(s) || b.stream_writes.contains(s) {
            reasons.push(format!("stream `{s}` (emit in `{}`)", a.system_name));
        }
    }
    for s in &b.stream_writes {
        if a.stream_reads.contains(s) && !a.stream_writes.contains(s) {
            reasons.push(format!("stream `{s}` (emit in `{}`)", b.system_name));
        }
    }

    for qa in &a.queries {
        for qb in &b.queries {
            for c in qa.conflicting_storages_with(qb) {
                let msg = format!("component `{c}`");
                if !reasons.contains(&msg) {
                    reasons.push(msg);
                }
            }
        }
    }

    reasons
}

/// Builds the full pairwise [`ConcurrencyGraph`] over all analyzed systems/tasks.
pub fn build_concurrency_graph(systems: &[FilteredAccessSet]) -> ConcurrencyGraph {
    let mut graph = ConcurrencyGraph {
        systems: systems.iter().map(|s| s.system_name.clone()).collect(),
        conflicts: Vec::new(),
    };
    for i in 0..systems.len() {
        for j in (i + 1)..systems.len() {
            let reasons = system_conflicts(&systems[i], &systems[j]);
            if !reasons.is_empty() {
                graph.conflicts.push(ConflictEdge {
                    system_a: systems[i].system_name.clone(),
                    system_b: systems[j].system_name.clone(),
                    reasons,
                });
            }
        }
    }
    graph
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `modes_conflict` is symmetric and allows shared reads or filter-only access.
    #[test]
    fn modes_conflict_matrix_and_symmetry() {
        let all = [
            TermAccessMode::Read,
            TermAccessMode::Write,
            TermAccessMode::SelectiveWrite,
            TermAccessMode::With,
            TermAccessMode::Without,
            TermAccessMode::ResRead,
        ];
        for &a in &all {
            for &b in &all {
                assert_eq!(modes_conflict(a, b), modes_conflict(b, a));
            }
        }
        assert!(!modes_conflict(TermAccessMode::Read, TermAccessMode::Read));
        assert!(modes_conflict(TermAccessMode::Read, TermAccessMode::Write));
        assert!(!modes_conflict(TermAccessMode::With, TermAccessMode::Write));
    }

    /// Verifies `storage_keys_overlap` distinguishes disjoint `@soa` strata cleanly.
    #[test]
    fn soa_strata_overlap_rules() {
        assert!(!storage_keys_overlap("Body::hot", "Body::cold"));
        assert!(storage_keys_overlap("Body::hot", "Body"));
        assert!(storage_keys_overlap("Pos", "Pos"));
    }
}
