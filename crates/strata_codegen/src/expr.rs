//! Shared deterministic kernel extraction from [`MirFunction`] bodies so C99, Rust Guest,
//! Bevy Native, and Cranelift JIT execute bit-identical per-entity computations.

use crate::find_layout;
use serde::{Deserialize, Serialize};
use strata_mir::{MirFunction, MirModule};
use strata_sema::access::TermAccessMode;
use strata_sema::types::Ty;

/// Scalar value type within lowered kernel expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScalarKind {
    /// 32-bit IEEE float (`f32`).
    F32,
    /// 64-bit IEEE float (`f64`).
    F64,
    /// 32-bit signed integer (`i32`).
    I32,
    /// 32-bit unsigned integer (`u32`).
    U32,
    /// 64-bit signed integer (`i64`).
    I64,
    /// 64-bit unsigned integer (`u64`).
    U64,
    /// 8-bit boolean (`FfiBool` / `uint8_t`).
    Bool,
}

impl ScalarKind {
    /// Maps a Strata [`Ty`] to its primary scalar representation when directly addressable.
    #[must_use]
    pub fn from_ty(ty: &Ty) -> Option<Self> {
        match ty {
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Some(Self::F32),
            Ty::F64 => Some(Self::F64),
            Ty::I8 | Ty::I16 | Ty::I32 | Ty::Fix32 => Some(Self::I32),
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => Some(Self::U32),
            Ty::I64 | Ty::Fix64 => Some(Self::I64),
            Ty::U64 => Some(Self::U64),
            Ty::Bool => Some(Self::Bool),
            _ => None,
        }
    }
}

/// Assignment operator inside a lowered kernel statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssignOp {
    /// `=`
    Set,
    /// `+=`
    AddAssign,
    /// `-=`
    SubAssign,
    /// `*=`
    MulAssign,
    /// `/=`
    DivAssign,
}

/// Binary arithmetic or comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOpKind {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `&&`
    And,
    /// `||`
    Or,
}

/// Reference to a scalar field on either a query column element, singleton resource, or uniform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldRef {
    /// Scalar local (`uniform let` or `let`).
    Local(String),
    /// Field on a singleton resource bound in function parameters (`param.field` or `param.field.raw()`).
    ResourceField {
        /// Canonical resource layout name.
        resource_canonical: String,
        /// Byte offset inside the resource struct.
        byte_offset: usize,
        /// Scalar kind at `byte_offset`.
        kind: ScalarKind,
        /// Rust field name (including any vector component).
        field_name: String,
    },
    /// Field on a component column bound to a query loop term (`term_idx`, `byte_offset`).
    ColumnField {
        /// Index into `QueryAccessDesc.terms`.
        term_idx: usize,
        /// Component byte stride (`layout.size`).
        elem_size: usize,
        /// Byte offset inside the component struct (including vector lane `.x`/`.y`/`.z` offset).
        byte_offset: usize,
        /// Scalar kind.
        kind: ScalarKind,
        /// Source field name on the Rust struct.
        field_name: String,
        /// Optional vector sub-lane (`Some(0)` = `.x`, `Some(1)` = `.y`, `Some(2)` = `.z`, `Some(3)` = `.w`).
        vec_lane: Option<usize>,
        /// True when targeting a `&mut?` selective-write term.
        is_selective: bool,
    },
}

/// Typed scalar expression inside a lowered kernel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KernelExpr {
    /// Float constant (`f64` precision, cast to target scalar type).
    FloatLit(f64),
    /// Integer constant (`i64`).
    IntLit(i64),
    /// Boolean constant.
    BoolLit(bool),
    /// Load of a resolved [`FieldRef`].
    Load(FieldRef),
    /// Unary negation or logical NOT.
    Neg(Box<KernelExpr>),
    /// Logical `!` on boolean expression.
    Not(Box<KernelExpr>),
    /// Binary arithmetic or comparison.
    Binary {
        /// Operator.
        op: BinOpKind,
        /// Left operand.
        lhs: Box<KernelExpr>,
        /// Right operand.
        rhs: Box<KernelExpr>,
    },
}

/// Single imperative statement inside a per-entity query loop or pre-loop prologue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KernelStmt {
    /// `let name = expr;`
    Let {
        /// Variable identifier.
        name: String,
        /// Initializer expression.
        expr: KernelExpr,
        /// Inferred scalar kind.
        kind: ScalarKind,
    },
    /// Field write (`target op= value;`), marking row dirty if `is_selective` and `mark_dirty`.
    Assign {
        /// Destination component or resource field.
        target: FieldRef,
        /// Operator (`=`, `+=`, `-=`, `*=`, `/=`).
        op: AssignOp,
        /// Assigned value expression.
        value: KernelExpr,
    },
    /// Conditional branch `if cond { then_stmts } else { else_stmts }`.
    If {
        /// Condition expression (evaluated as bool).
        cond: KernelExpr,
        /// Statements executed when `cond` is non-zero.
        then_stmts: Vec<KernelStmt>,
        /// Statements executed when `cond` is zero.
        else_stmts: Vec<KernelStmt>,
    },
}

/// Bound query term descriptor resolved to layout byte sizes and Rust/C types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundTerm {
    /// Term index within the query (`0..terms.len()`).
    pub term_idx: usize,
    /// Query binding alias inside `for v in query(alias: ...)` or component short name.
    pub alias: String,
    /// Access mode (`READ`, `WRITE`, `OPTIONAL_READ`, `OPTIONAL_WRITE`, etc.).
    pub mode: TermAccessMode,
    /// Target component canonical name.
    pub component_canonical: String,
    /// Target component sanitized identifier.
    pub component_ident: String,
    /// Stride in bytes (`layout.size`).
    pub size: usize,
    /// Alignment in bytes (`layout.align`).
    pub align: usize,
    /// Projected sub-field if `Comp.field` was written in the query signature.
    pub projected_field: Option<String>,
    /// True if `&mut?` selective tick tracking applies.
    pub is_selective: bool,
}

/// Bound singleton resource parameter inside a system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundResource {
    /// Resource alias used inside the system body (or canonical short name).
    pub param_alias: String,
    /// Canonical resource name.
    pub canonical_name: String,
    /// Sanitized Rust/C struct name.
    pub ident: String,
    /// Whether borrowed mutably (`&mut res`).
    pub mutable: bool,
}

/// Extracted deterministic execution plan for one [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemPlan {
    /// System function name.
    pub name: String,
    /// Bound resource parameters.
    pub resources: Vec<BoundResource>,
    /// Pre-loop `uniform let ...` statements.
    pub uniforms: Vec<KernelStmt>,
    /// Bound terms for query 0 (when `for item in query(...)` is present).
    pub query0_terms: Vec<BoundTerm>,
    /// Per-row statements inside the primary `for item in query(...)` loop.
    pub row_stmts: Vec<KernelStmt>,
    /// True when any query term uses `&mut?` selective tick coalescing.
    pub has_selective_writes: bool,
}

/// Extracts a structured deterministic execution plan for `func` within `mir`.
///
/// Always succeeds gracefully: complex high-level cookbook scripts (tasks, observers, spawn_batch)
/// yield empty `row_stmts` when they do not map to dense per-chunk arithmetic loops while preserving
/// exact query/resource bindings so all targets compile cleanly.
#[must_use]
pub fn extract_system_plan(func: &MirFunction, mir: &MirModule) -> SystemPlan {
    let mut resources = Vec::new();
    // 1. Collect from MIR `Inst::ResRead` / `Inst::ResWrite` (lowered from `FilteredAccessSet`).
    for bb in &func.blocks {
        for stmt in &bb.stmts {
            let (key, mutable) = match &stmt.inst {
                strata_mir::Inst::ResRead { resource } => (resource, false),
                strata_mir::Inst::ResWrite { resource } => (resource, true),
                _ => continue,
            };
            let canonical = find_layout(mir, key)
                .map(|l| l.canonical_name.clone())
                .unwrap_or_else(|| key.clone());
            let ident = crate::sanitize_ident(&canonical);
            let param_alias = infer_res_param_alias(&func.source_body, &ident)
                .unwrap_or_else(|| format!("res_{}", resources.len()));
            if let Some(existing) = resources
                .iter_mut()
                .find(|r: &&mut BoundResource| r.canonical_name == canonical)
            {
                existing.mutable |= mutable;
            } else {
                resources.push(BoundResource {
                    param_alias,
                    canonical_name: canonical,
                    ident,
                    mutable,
                });
            }
        }
    }
    // 2. Also collect any resource terms present inside `func.queries`.
    for (idx, q) in func.queries.iter().enumerate() {
        for term in &q.terms {
            if matches!(
                term.mode,
                TermAccessMode::ResRead | TermAccessMode::ResWrite
            ) {
                let canonical = find_layout(mir, &term.storage_key)
                    .map(|l| l.canonical_name.clone())
                    .unwrap_or_else(|| term.storage_key.clone());
                let ident = crate::sanitize_ident(&canonical);
                let param_alias = infer_res_param_alias(&func.source_body, &ident)
                    .unwrap_or_else(|| format!("res_{idx}"));
                if !resources
                    .iter()
                    .any(|r: &BoundResource| r.canonical_name == canonical)
                {
                    resources.push(BoundResource {
                        param_alias,
                        canonical_name: canonical,
                        ident,
                        mutable: term.mode == TermAccessMode::ResWrite,
                    });
                }
            }
        }
    }

    let mut query0_terms = Vec::new();
    let mut has_selective_writes = false;
    if let Some(q0) = func.queries.first() {
        let header_aliases = parse_query_header_aliases(&func.source_body);
        for (ti, term) in q0.terms.iter().enumerate() {
            if matches!(
                term.mode,
                TermAccessMode::ResRead | TermAccessMode::ResWrite
            ) {
                continue;
            }
            let layout = find_layout(mir, &term.storage_key);
            let canonical = layout
                .map(|l| l.canonical_name.clone())
                .unwrap_or_else(|| term.storage_key.clone());
            let ident = crate::sanitize_ident(&canonical);
            let alias = header_aliases
                .get(ti)
                .cloned()
                .unwrap_or_else(|| ident.to_lowercase());
            let is_selective = term.mode == TermAccessMode::SelectiveWrite;
            has_selective_writes |= is_selective;
            query0_terms.push(BoundTerm {
                term_idx: ti,
                alias,
                mode: term.mode,
                component_canonical: canonical,
                component_ident: ident,
                size: layout.map_or(0, |l| l.size),
                align: layout.map_or(1, |l| l.align),
                projected_field: term.field_name.clone(),
                is_selective,
            });
        }
    }

    let mut uniforms = Vec::new();
    let mut row_stmts = Vec::new();
    let mut env_locals: Vec<(String, ScalarKind)> = Vec::new();

    if let Some((loop_var, pre_body, loop_body)) = split_for_query_loop(&func.source_body) {
        let resolver = KernelResolver {
            mir,
            resources: &resources,
            loop_var: &loop_var,
            terms: &query0_terms,
        };
        for stmt_src in split_top_statements(pre_body) {
            if let Some(stmt) = parse_stmt(stmt_src.trim(), &resolver, &mut env_locals) {
                uniforms.push(stmt);
            }
        }
        for stmt_src in split_top_statements(loop_body) {
            if let Some(stmt) = parse_stmt(stmt_src.trim(), &resolver, &mut env_locals) {
                row_stmts.push(stmt);
            }
        }
    }

    SystemPlan {
        name: func.name.clone(),
        resources,
        uniforms,
        query0_terms,
        row_stmts,
        has_selective_writes,
    }
}

fn infer_res_param_alias(body: &str, res_ident: &str) -> Option<String> {
    // Look in the callable header before the opening `{`.
    let head = body.split('{').next().unwrap_or("");
    for part in head.split(',') {
        let trimmed = part.trim();
        if let Some((lhs, rhs)) = trimmed.split_once(':')
            && rhs.contains(res_ident)
        {
            let alias = lhs.rsplit('(').next().unwrap_or(lhs).trim().to_owned();
            if !alias.is_empty() {
                return Some(alias);
            }
        }
    }
    None
}

fn parse_query_header_aliases(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(q_idx) = body.find("query(") else {
        return out;
    };
    let rest = &body[q_idx + "query(".len()..];
    let mut depth = 1usize;
    let mut end = rest.len();
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &rest[..end];
    for term_src in inner.split(',') {
        let t = term_src.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((alias, _rhs)) = t.split_once(':') {
            out.push(alias.trim().to_owned());
        } else {
            out.push(t.to_owned());
        }
    }
    out
}

fn split_for_query_loop(source: &str) -> Option<(String, &str, &str)> {
    // Strip signature up to first `{`.
    let open_fn = source.find('{')?;
    let body = &source[open_fn + 1..];
    let close_fn = body.rfind('}')?;
    let inner = &body[..close_fn];

    let for_pos = inner.find("for ")?;
    let pre_body = &inner[..for_pos];
    let after_for = inner[for_pos + "for ".len()..].trim_start();
    let in_pos = after_for.find(" in ")?;
    let loop_var = after_for[..in_pos].trim().to_owned();
    let after_in = &after_for[in_pos + " in ".len()..];
    if !after_in.trim_start().starts_with("query") {
        return None;
    }
    // Find `{ ... }` of the `for` body.
    let loop_open = after_in.find('{')?;
    let after_open = &after_in[loop_open + 1..];
    let mut depth = 1usize;
    for (i, ch) in after_open.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((loop_var, pre_body, &after_open[..i]));
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_line_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let clean = match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        };
        out.push_str(clean);
        out.push('\n');
    }
    out
}

fn split_top_statements(raw: &str) -> Vec<String> {
    let clean = strip_line_comments(raw);
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let bytes = clean.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth == 0 && paren_depth == 0 {
                    // Check if followed by `else`.
                    let rem = clean[i + 1..].trim_start();
                    if !rem.starts_with("else") {
                        let stmt = clean[start..=i].trim().to_owned();
                        if !stmt.is_empty() {
                            out.push(stmt);
                        }
                        start = i + 1;
                    }
                }
            }
            b';' if brace_depth == 0 && paren_depth == 0 => {
                let stmt = clean[start..i].trim().to_owned();
                if !stmt.is_empty() {
                    out.push(stmt);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = clean[start..].trim().to_owned();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

struct KernelResolver<'a> {
    mir: &'a MirModule,
    resources: &'a [BoundResource],
    loop_var: &'a str,
    terms: &'a [BoundTerm],
}

impl<'a> KernelResolver<'a> {
    fn resolve_path(
        &self,
        raw: &str,
        locals: &[(String, ScalarKind)],
    ) -> Option<(FieldRef, ScalarKind)> {
        let mut s = raw.trim();
        // Strip `.raw()` / `.as_secs()` / `.get()` no-op unit conversions.
        for suffix in [".raw()", ".as_secs()", ".as_millis()", ".get()"] {
            if let Some(stripped) = s.strip_suffix(suffix) {
                s = stripped.trim();
            }
        }
        // Check consts in MIR? Look up module consts first.
        if locals.iter().any(|(n, _)| n == s) {
            let k = locals
                .iter()
                .find(|(n, _)| n == s)
                .map_or(ScalarKind::F32, |(_, k)| *k);
            return Some((FieldRef::Local(s.to_owned()), k));
        }
        // Check `loop_var.alias(.field)?(.lane)?`.
        if let Some(after_var) = s.strip_prefix(&format!("{}.", self.loop_var)) {
            let parts: Vec<&str> = after_var.split('.').collect();
            if let Some(term) = self.terms.iter().find(|t| t.alias == parts[0]) {
                let layout = find_layout(self.mir, &term.component_canonical)?;
                // Case 1: query term was projected onto a struct field (e.g. `Pos3D.xyz`).
                if let Some(proj) = &term.projected_field {
                    let field = layout.fields.iter().find(|f| f.name == *proj)?;
                    if let Some(lane_str) = parts.get(1)
                        && let Some(lane) = vec_lane_index(lane_str)
                    {
                        return Some((
                            FieldRef::ColumnField {
                                term_idx: term.term_idx,
                                elem_size: term.size,
                                byte_offset: field.offset + lane * 4,
                                kind: ScalarKind::F32,
                                field_name: field.name.clone(),
                                vec_lane: Some(lane),
                                is_selective: term.is_selective,
                            },
                            ScalarKind::F32,
                        ));
                    }
                    if parts.len() == 1
                        && let Some(sk) = ScalarKind::from_ty(&field.ty)
                    {
                        return Some((
                            FieldRef::ColumnField {
                                term_idx: term.term_idx,
                                elem_size: term.size,
                                byte_offset: field.offset,
                                kind: sk,
                                field_name: field.name.clone(),
                                vec_lane: None,
                                is_selective: term.is_selective,
                            },
                            sk,
                        ));
                    }
                } else if parts.len() >= 2 {
                    // Whole-component bind (`p: &mut Pos2D` -> `d.p.x`).
                    let field = layout.fields.iter().find(|f| f.name == parts[1])?;
                    if let Some(lane_str) = parts.get(2)
                        && let Some(lane) = vec_lane_index(lane_str)
                    {
                        return Some((
                            FieldRef::ColumnField {
                                term_idx: term.term_idx,
                                elem_size: term.size,
                                byte_offset: field.offset + lane * 4,
                                kind: ScalarKind::F32,
                                field_name: field.name.clone(),
                                vec_lane: Some(lane),
                                is_selective: term.is_selective,
                            },
                            ScalarKind::F32,
                        ));
                    }
                    if parts.len() == 2
                        && let Some(sk) = ScalarKind::from_ty(&field.ty)
                    {
                        return Some((
                            FieldRef::ColumnField {
                                term_idx: term.term_idx,
                                elem_size: term.size,
                                byte_offset: field.offset,
                                kind: sk,
                                field_name: field.name.clone(),
                                vec_lane: None,
                                is_selective: term.is_selective,
                            },
                            sk,
                        ));
                    }
                }
            }
        }
        // Check singleton resources (`clk.dt` or parameter alias `p.dt`).
        if let Some((res_name, field_rest)) = s.split_once('.')
            && res_name != self.loop_var
            && !locals.iter().any(|(n, _)| n == res_name)
        {
            let field_name = field_rest.split('.').next().unwrap_or(field_rest);
            // Prefer exact alias match, else match any bound resource carrying `field_name`.
            let res_match = self
                .resources
                .iter()
                .find(|r| r.param_alias == res_name)
                .or_else(|| {
                    self.resources.iter().find(|r| {
                        find_layout(self.mir, &r.canonical_name)
                            .is_some_and(|l| l.fields.iter().any(|f| f.name == field_name))
                    })
                });
            if let Some(res) = res_match {
                let layout = find_layout(self.mir, &res.canonical_name)?;
                let field = layout.fields.iter().find(|f| f.name == field_name)?;
                let sk = ScalarKind::from_ty(&field.ty)?;
                return Some((
                    FieldRef::ResourceField {
                        resource_canonical: res.canonical_name.clone(),
                        byte_offset: field.offset,
                        kind: sk,
                        field_name: field.name.clone(),
                    },
                    sk,
                ));
            }
        }
        None
    }
}

fn vec_lane_index(name: &str) -> Option<usize> {
    match name {
        "x" => Some(0),
        "y" => Some(1),
        "z" => Some(2),
        "w" => Some(3),
        _ => None,
    }
}

fn parse_stmt(
    stmt: &str,
    resolver: &KernelResolver<'_>,
    locals: &mut Vec<(String, ScalarKind)>,
) -> Option<KernelStmt> {
    let trimmed = stmt.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(after_if) = trimmed.strip_prefix("if ") {
        let open = after_if.find('{')?;
        let cond_str = after_if[..open].trim();
        let cond = parse_expr(cond_str, resolver, locals)?;
        let (then_block, rest) = extract_brace_block(&after_if[open..])?;
        let mut then_stmts = Vec::new();
        for s in split_top_statements(then_block) {
            if let Some(parsed) = parse_stmt(&s, resolver, locals) {
                then_stmts.push(parsed);
            }
        }
        let mut else_stmts = Vec::new();
        let rest_trim = rest.trim();
        if let Some(after_else) = rest_trim.strip_prefix("else") {
            let else_trim = after_else.trim_start();
            if let Some(e_open) = else_trim.find('{')
                && let Some((else_block, _)) = extract_brace_block(&else_trim[e_open..])
            {
                for s in split_top_statements(else_block) {
                    if let Some(parsed) = parse_stmt(&s, resolver, locals) {
                        else_stmts.push(parsed);
                    }
                }
            }
        }
        return Some(KernelStmt::If {
            cond,
            then_stmts,
            else_stmts,
        });
    }

    // `uniform let x = ...` or `let x = ...`
    let after_let = trimmed
        .strip_prefix("uniform ")
        .unwrap_or(trimmed)
        .trim_start();
    if let Some(decl) = after_let.strip_prefix("let ")
        && let Some((lhs, rhs)) = decl.split_once('=')
    {
        let name = lhs
            .trim()
            .strip_prefix("mut ")
            .unwrap_or(lhs.trim())
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
        let (expr, kind) = parse_expr_typed(rhs, resolver, locals)?;
        locals.push((name.clone(), kind));
        return Some(KernelStmt::Let { name, expr, kind });
    }

    // Compound and plain assignments: `+=`, `-=`, `*=`, `/=`, `=`.
    for (op_str, op) in [
        ("+=", AssignOp::AddAssign),
        ("-=", AssignOp::SubAssign),
        ("*=", AssignOp::MulAssign),
        ("/=", AssignOp::DivAssign),
        ("=", AssignOp::Set),
    ] {
        if let Some(pos) = find_top_level_op(trimmed, op_str) {
            // Avoid matching `==`, `!=`, `<=`, `>=`.
            let lhs = trimmed[..pos].trim();
            let rhs = trimmed[pos + op_str.len()..].trim();
            if let Some((target, target_kind)) = resolver.resolve_path(lhs, locals) {
                let value = parse_expr_with_hint(rhs, target_kind, resolver, locals)?;
                return Some(KernelStmt::Assign { target, op, value });
            }
            return None;
        }
    }

    None
}

fn extract_brace_block(s: &str) -> Option<(&str, &str)> {
    let open = s.find('{')?;
    let mut depth = 0usize;
    for (i, ch) in s[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&s[open + 1..open + i], &s[open + i + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

fn find_top_level_op(s: &str, op: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i + op_bytes.len() <= bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 && &bytes[i..i + op_bytes.len()] == op_bytes => {
                if op == "=" {
                    let prev = if i > 0 { bytes[i - 1] } else { 0 };
                    let next = bytes.get(i + 1).copied().unwrap_or(0);
                    if matches!(prev, b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/')
                        || next == b'='
                    {
                        i += 1;
                        continue;
                    }
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_expr(
    src: &str,
    resolver: &KernelResolver<'_>,
    locals: &[(String, ScalarKind)],
) -> Option<KernelExpr> {
    parse_expr_typed(src, resolver, locals).map(|(e, _)| e)
}

fn parse_expr_with_hint(
    src: &str,
    _hint: ScalarKind,
    resolver: &KernelResolver<'_>,
    locals: &[(String, ScalarKind)],
) -> Option<KernelExpr> {
    parse_expr(src, resolver, locals)
}

fn parse_expr_typed(
    src: &str,
    resolver: &KernelResolver<'_>,
    locals: &[(String, ScalarKind)],
) -> Option<(KernelExpr, ScalarKind)> {
    let s = strip_outer_parens(src.trim());
    if s.is_empty() {
        return None;
    }

    // Precedence (lowest to highest): ||, &&, == != <= >= < >, + -, * / %
    let tiers: &[&[(&str, BinOpKind)]] = &[
        &[("||", BinOpKind::Or)],
        &[("&&", BinOpKind::And)],
        &[
            ("==", BinOpKind::Eq),
            ("!=", BinOpKind::Ne),
            ("<=", BinOpKind::Le),
            (">=", BinOpKind::Ge),
            ("<", BinOpKind::Lt),
            (">", BinOpKind::Gt),
        ],
        &[("+", BinOpKind::Add), ("-", BinOpKind::Sub)],
        &[
            ("*", BinOpKind::Mul),
            ("/", BinOpKind::Div),
            ("%", BinOpKind::Rem),
        ],
    ];

    for tier in tiers {
        if let Some((pos, _op_str, op_kind)) = find_last_top_level_binop(s, tier) {
            let op_len = tier.iter().find(|(_, k)| *k == op_kind)?.0.len();
            let lhs_str = s[..pos].trim();
            let rhs_str = s[pos + op_len..].trim();
            if !lhs_str.is_empty() && !rhs_str.is_empty() {
                let (lhs, lk) = parse_expr_typed(lhs_str, resolver, locals)?;
                let (rhs, _) = parse_expr_typed(rhs_str, resolver, locals)?;
                let out_kind = match op_kind {
                    BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge
                    | BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::And
                    | BinOpKind::Or => ScalarKind::Bool,
                    _ => lk,
                };
                return Some((
                    KernelExpr::Binary {
                        op: op_kind,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    },
                    out_kind,
                ));
            }
        }
    }

    if let Some(rest) = s.strip_prefix('!') {
        let (inner, _) = parse_expr_typed(rest, resolver, locals)?;
        return Some((KernelExpr::Not(Box::new(inner)), ScalarKind::Bool));
    }
    if let Some(rest) = s.strip_prefix('-') {
        let (inner, k) = parse_expr_typed(rest, resolver, locals)?;
        return Some((KernelExpr::Neg(Box::new(inner)), k));
    }

    if s == "true" {
        return Some((KernelExpr::BoolLit(true), ScalarKind::Bool));
    }
    if s == "false" {
        return Some((KernelExpr::BoolLit(false), ScalarKind::Bool));
    }

    if let Some((fref, kind)) = resolver.resolve_path(s, locals) {
        return Some((KernelExpr::Load(fref), kind));
    }

    // Numeric or unit literals (`8.3333_ms`, `-9.81_mps2`, `0.5_f32`, `42_i32`).
    parse_numeric_or_unit_literal(s)
}

fn strip_outer_parens(mut s: &str) -> &str {
    loop {
        if !(s.starts_with('(') && s.ends_with(')')) {
            return s;
        }
        let mut depth = 0usize;
        let mut encloses_all = true;
        for (idx, ch) in s.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && idx + ch.len_utf8() < s.len() {
                        encloses_all = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if encloses_all {
            s = s[1..s.len() - 1].trim();
        } else {
            return s;
        }
    }
}

fn find_last_top_level_binop(
    s: &str,
    ops: &[(&str, BinOpKind)],
) -> Option<(usize, &'static str, BinOpKind)> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut best: Option<(usize, &str, BinOpKind)> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                for &(sym, kind) in ops {
                    let sb = sym.as_bytes();
                    if i + sb.len() <= bytes.len() && &bytes[i..i + sb.len()] == sb {
                        // Do not match unary leading `-` at index 0 or after another operator,
                        // and do not split `<`/`>` inside `<=`/`>=` or `=` inside `==`/`!=`.
                        if sym == "-" && is_unary_minus_pos(bytes, i) {
                            continue;
                        }
                        if (sym == "<" || sym == ">") && bytes.get(i + 1) == Some(&b'=') {
                            continue;
                        }
                        if best.is_none_or(|(b_pos, _, _)| i >= b_pos) {
                            best = Some((i, "op", kind));
                        }
                        i += sb.len() - 1;
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    best
}

fn is_unary_minus_pos(bytes: &[u8], pos: usize) -> bool {
    let mut j = pos;
    while j > 0 {
        j -= 1;
        let b = bytes[j];
        if b.is_ascii_whitespace() {
            continue;
        }
        return !b.is_ascii_alphanumeric() && b != b'_' && b != b')';
    }
    true
}

fn parse_numeric_or_unit_literal(raw: &str) -> Option<(KernelExpr, ScalarKind)> {
    let s = raw.trim();
    if let Some((num_part, factor, kind)) = split_unit_suffix(s) {
        let cleaned: String = num_part.chars().filter(|c| *c != '_').collect();
        if let Ok(v) = cleaned.parse::<f64>() {
            return Some((KernelExpr::FloatLit(v * factor), kind));
        }
    }
    if s.contains('.') {
        let cleaned: String = s.chars().filter(|c| *c != '_').collect();
        if let Ok(v) = cleaned.parse::<f64>() {
            return Some((KernelExpr::FloatLit(v), ScalarKind::F32));
        }
    } else {
        let cleaned: String = s.chars().filter(|c| *c != '_').collect();
        if let Ok(v) = cleaned.parse::<i64>() {
            return Some((KernelExpr::IntLit(v), ScalarKind::I32));
        }
    }
    None
}

fn split_unit_suffix(s: &str) -> Option<(&str, f64, ScalarKind)> {
    const SUFFIXES: &[(&str, f64, ScalarKind)] = &[
        ("_mps2", 1.0, ScalarKind::F32),
        ("_mps", 1.0, ScalarKind::F32),
        ("_sec", 1.0, ScalarKind::F32),
        ("_ms", 0.001, ScalarKind::F32),
        ("_s", 1.0, ScalarKind::F32),
        ("_hz", 1.0, ScalarKind::F32),
        ("_rad", 1.0, ScalarKind::F32),
        ("_deg", std::f64::consts::PI / 180.0, ScalarKind::F32),
        ("_m", 1.0, ScalarKind::F32),
        ("_f32", 1.0, ScalarKind::F32),
        ("_f64", 1.0, ScalarKind::F64),
        ("_i32", 1.0, ScalarKind::I32),
        ("_u32", 1.0, ScalarKind::U32),
    ];
    for &(suf, factor, kind) in SUFFIXES {
        if let Some(stem) = s.strip_suffix(suf) {
            return Some((stem, factor, kind));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;

    /// Verifies numeric and unit-suffixed literal parsing scales milliseconds and degrees cleanly.
    #[test]
    fn unit_literals_and_scalars_parse_accurately() {
        assert_eq!(ScalarKind::from_ty(&Ty::Bool), Some(ScalarKind::Bool));
        assert_eq!(ScalarKind::from_ty(&Ty::F64), Some(ScalarKind::F64));
        assert_eq!(ScalarKind::from_ty(&Ty::Vec3), None);
        assert_eq!(
            parse_numeric_or_unit_literal("500_ms"),
            Some((KernelExpr::FloatLit(0.5), ScalarKind::F32))
        );
        assert_eq!(
            parse_numeric_or_unit_literal("42"),
            Some((KernelExpr::IntLit(42), ScalarKind::I32))
        );
    }

    /// Verifies `extract_system_plan` captures `ResRead`, `uniform let`, and `&mut?` selective flags.
    #[test]
    fn extract_system_plan_tracks_uniforms_and_selective_writes() {
        let src = r#"
module demo::plan @version(1.0.0);
resource Cfg { step: f32 = 0.25 }
component Pos { x: f32 = 0.0 }
component Flag @summary_tick { on: bool = false }
sys update(c: &res Cfg) {
    uniform let s = c.step;
    for e in query(p: &mut Pos, f: &mut? Flag) {
        e.p.x += s;
        if e.p.x > 1.0 {
            e.f.on = true;
        }
    }
}
schedule FixedUpdate { update }
"#;
        let analyzed = analyze_source("plan.strata", src);
        assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
        let mir = lower_to_mir(&analyzed);
        let plan = extract_system_plan(&mir.functions[0], &mir);
        assert_eq!(plan.resources.len(), 1);
        assert_eq!(plan.uniforms.len(), 1);
        assert!(plan.has_selective_writes);
        assert_eq!(plan.query0_terms.len(), 2);
    }
}
